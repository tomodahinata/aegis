import type { NextConfig } from 'next';

// Note: NO Content-Security-Policy here. `secure()` in middleware.ts is the single CSP emitter.
const nextConfig: NextConfig = {
  reactStrictMode: true,
};

export default nextConfig;
