import type { NextConfig } from 'next';

// No Content-Security-Policy here — secure() in middleware.ts is the single CSP emitter.
const nextConfig: NextConfig = {
  reactStrictMode: true,
};

export default nextConfig;
