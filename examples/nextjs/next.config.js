/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable standalone output for Docker deployments
  // This creates a minimal production build in .next/standalone
  output: 'standalone',

  // Ensure server components can use the keystore
  // Note: In Next.js 14+, use serverExternalPackages instead of experimental.serverComponentsExternalPackages
  serverExternalPackages: ['@faizahmedfarooqui/secret-keystore'],
};

module.exports = nextConfig;

