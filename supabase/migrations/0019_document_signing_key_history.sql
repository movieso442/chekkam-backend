-- Preserve the exact trusted public key that validated a document when it
-- was issued. Institutions can then rotate a lost/compromised signing key
-- without making previously genuine records appear Tampered.
--
-- The key history is server-managed: ordinary institution members cannot add
-- keys, and a trigger permits a document snapshot only when it is already in
-- the issuer's registered key history.

create table if not exists institution_signing_keys (
  institution_id uuid not null references institutions(id) on delete cascade,
  public_key text not null,
  activated_at timestamptz not null default now(),
  retired_at timestamptz,
  primary key (institution_id, public_key)
);

alter table institution_signing_keys enable row level security;

-- No client-facing write policy is intentional. Key registration and rotation
-- run only through the service-role backend / explicit admin script.
create policy "institution_signing_keys_select_staff" on institution_signing_keys
  for select using (is_staff());

alter table documents add column if not exists signing_public_key_snapshot text;

-- Register the current issuer key first, then give every existing document a
-- durable snapshot of that key before any future rotation takes place.
insert into institution_signing_keys (institution_id, public_key)
select id, signing_public_key
from institutions
where signing_public_key is not null
on conflict (institution_id, public_key) do nothing;

update documents as d
set signing_public_key_snapshot = i.signing_public_key
from institutions as i
where d.institution_id = i.id
  and d.signing_public_key_snapshot is null
  and i.signing_public_key is not null;

create or replace function document_signing_key_snapshot_is_registered()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Once present, a document's signing-key snapshot is immutable. This is
  -- evidence captured at issuance, not a mutable issuer profile field.
  if tg_op = 'UPDATE'
     and old.signing_public_key_snapshot is not null
     and new.signing_public_key_snapshot is distinct from old.signing_public_key_snapshot then
    raise exception 'document signing key snapshot is immutable';
  end if;

  if new.signing_public_key_snapshot is not null
     and not exists (
       select 1
       from institution_signing_keys as k
       where k.institution_id = new.institution_id
         and k.public_key = new.signing_public_key_snapshot
     ) then
    raise exception 'document signing key is not registered for this institution';
  end if;

  return new;
end;
$$;

drop trigger if exists documents_validate_signing_key_snapshot on documents;
create trigger documents_validate_signing_key_snapshot
before insert or update of institution_id, signing_public_key_snapshot on documents
for each row execute function document_signing_key_snapshot_is_registered();

comment on column documents.signing_public_key_snapshot is
  'Immutable issuer public-key snapshot used to validate this document after an institution rotates keys.';
