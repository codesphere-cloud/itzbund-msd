export const config = {
  isProduction: process.env.NODE_ENV === "production",
  clientTimeout: 45_000,
  clientRetries: 1,
  statFirstDay: new Date(Date.UTC(2023, 0, 15)),
  generateStatsForCollections: (
    process.env.NEXT_PUBLIC_REFERENCE_COLLECTIONS ?? ""
  )
    .split(",")
    .map((d) => +d)
    .filter((d) => !isNaN(d))
    .filter((d) => d > 0),
  canonicalUrl: process.env.CANONICAL_URL,
  influx: {
    url: process.env.INFLUX_URL as string,
    token: process.env.INFLUX_TOKEN as string,
    org: process.env.INFLUX_ORG as string,
    bucket: process.env.INFLUX_BUCKET as string,
  },
  socks5Proxy: process.env.SOCKS5_PROXY,
  scanReportDurationThresholdUntilValidation: 10_000,
};
