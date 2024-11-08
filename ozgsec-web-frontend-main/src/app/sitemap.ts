import { MetadataRoute } from "next";
import { testFqdn } from "../utils/common";
import { config } from "../config";

const baseUrl: String | undefined = config.canonicalUrl;

// will be statically optimized at build time
// therefore we can use the date - which will be the build date
export default function sitemap(): MetadataRoute.Sitemap {
  const imprintUrl: string =
    process.env.NEXT_PUBLIC_IMPRINT_URL || "/impressum";

  return [
    ...["/", imprintUrl, "/datenschutz", "/info"].map((entry) => {
      const isFqdn = testFqdn(entry);

      return {
        url: isFqdn ? entry : `${baseUrl}${entry}`,
        lastModified: new Date(),
      };
    }),
  ];
}
