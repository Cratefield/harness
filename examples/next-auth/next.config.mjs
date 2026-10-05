import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The repo root has its own package-lock.json, so Next would otherwise infer
  // /workspace as the tracing root (and warn). Pin it to this example.
  outputFileTracingRoot: here,
};

export default nextConfig;
