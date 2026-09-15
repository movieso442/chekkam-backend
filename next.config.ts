import type { NextConfig } from "next";

/**
 * The temporary Hostinger preview has a reproducible multipart request hang
 * in its local `/api/documents/sign` Route Handler. Keep the dashboard there
 * while proxying just its signing POST to the healthy Railway API. This is a
 * server-side rewrite: the browser stays same-origin and its Bearer token is
 * forwarded normally, so no CORS exception or credential duplication is
 * introduced. Railway never matches this Hostinger-only host condition.
 */
const HOSTINGER_SIGNING_PREVIEW_HOST = "slateblue-crow-308760\\.hostingersite\\.com";
const RAILWAY_SIGNING_UPSTREAM = "https://chekkam-backend-production.up.railway.app";

const nextConfig: NextConfig = {
  // @napi-rs/canvas ships a native binary (used for OCR page rasterization,
  // lib/ai/ocr.ts) that Turbopack/webpack can't bundle as an ESM chunk —
  // this tells Next.js to require it natively at runtime instead.
  serverExternalPackages: ["@napi-rs/canvas", "@contentauth/c2pa-node"],
  async rewrites() {
    return {
      beforeFiles: [
        {
          // `/api/documents/sign` only exposes POST, so this does not proxy
          // any other dashboard or public verification route.
          source: "/api/documents/sign",
          has: [{ type: "host", value: HOSTINGER_SIGNING_PREVIEW_HOST }],
          destination: `${RAILWAY_SIGNING_UPSTREAM}/api/documents/sign`,
        },
      ],
    };
  },
};

export default nextConfig;
