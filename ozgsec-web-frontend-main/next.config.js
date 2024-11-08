/** @type {import('next').NextConfig} */
module.exports = {
    reactStrictMode: true,
    swcMinify: true,
    webpack: (config, { isServer }) => {
        if (!isServer) {
            config.resolve.fallback.fs = false;
        }
        return config;
    },
    // pageExtensions: ['page.tsx', "api.ts", "page.ts"],
    i18n: {
        locales: ["de"],
        defaultLocale: "de",
    }
};
