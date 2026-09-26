/** @type {import('next').NextConfig} */
if (process.env.NODE_ENV === 'production') {
  const configured = process.env.NEXT_PUBLIC_API_BASE_URL;
  let apiOrigin;
  try {
    if (!configured) throw new Error();
    apiOrigin = new URL(configured);
  } catch {
    throw new Error('Production builds require an absolute NEXT_PUBLIC_API_BASE_URL.');
  }
  const apiHost = apiOrigin.hostname.toLowerCase();
  const isIpLiteral = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(apiHost) || apiHost.startsWith('[');
  const isDevelopmentHost =
    apiHost === 'localhost' || apiHost.endsWith('.localhost') || apiHost === 'testserver';
  if (
    apiOrigin.protocol !== 'https:' ||
    apiOrigin.username ||
    apiOrigin.password ||
    apiOrigin.search ||
    apiOrigin.hash ||
    (apiOrigin.pathname !== '/' && apiOrigin.pathname !== '') ||
    isIpLiteral ||
    isDevelopmentHost
  ) {
    throw new Error('Production NEXT_PUBLIC_API_BASE_URL must be a credential-free HTTPS origin.');
  }
}

const nextConfig = {
  reactStrictMode: true,
};

export default nextConfig;
