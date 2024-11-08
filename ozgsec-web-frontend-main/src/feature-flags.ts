export const featureFlags = {
  refreshEnabled: process.env.NEXT_PUBLIC_DISABLE_REFRESH !== "true",
  dashboardEnabled: process.env.NEXT_PUBLIC_DISABLE_DASHBOARD !== "true",
};
