import sitemap from "../app/sitemap";
import { testFqdn } from "./common";
import { config } from "../config";

describe("sitemap", () => {
  let baseUrl: String | undefined = config.canonicalUrl;

  const generateExpectedEntry = (url: string) => ({
    url: url,
    lastModified: expect.any(Date),
  });

  beforeEach(() => {
    process.env.NEXT_PUBLIC_IMPRINT_URL = "";
  });

  it("should include baseUrl for relative URLs", () => {
    process.env.NEXT_PUBLIC_IMPRINT_URL = "/impressum";

    const result = sitemap();

    expect(result).toEqual([
      generateExpectedEntry(`${baseUrl}/`),
      generateExpectedEntry(`${baseUrl}/impressum`),
      generateExpectedEntry(`${baseUrl}/datenschutz`),
      generateExpectedEntry(`${baseUrl}/info`),
    ]);
  });

  it("should not include baseUrl for full URLs", () => {
    process.env.NEXT_PUBLIC_IMPRINT_URL = "https://example.com/impressum";

    const result = sitemap();

    expect(result).toEqual([
      generateExpectedEntry(`${baseUrl}/`),
      generateExpectedEntry("https://example.com/impressum"),
      generateExpectedEntry(`${baseUrl}/datenschutz`),
      generateExpectedEntry(`${baseUrl}/info`),
    ]);
  });

  it('should default to "/impressum" if NEXT_PUBLIC_IMPRINT_URL is not set', () => {
    process.env.NEXT_PUBLIC_IMPRINT_URL = "";

    const result = sitemap();

    expect(result).toEqual([
      generateExpectedEntry(`${baseUrl}/`),
      generateExpectedEntry(`${baseUrl}/impressum`),
      generateExpectedEntry(`${baseUrl}/datenschutz`),
      generateExpectedEntry(`${baseUrl}/info`),
    ]);
  });

  it("should handle custom paths properly for NEXT_PUBLIC_IMPRINT_URL", () => {
    process.env.NEXT_PUBLIC_IMPRINT_URL = "/custom-impressum";

    const result = sitemap();

    expect(result).toEqual([
      generateExpectedEntry(`${baseUrl}/`),
      generateExpectedEntry(`${baseUrl}/custom-impressum`),
      generateExpectedEntry(`${baseUrl}/datenschutz`),
      generateExpectedEntry(`${baseUrl}/info`),
    ]);
  });
});

describe("testFqdn", () => {
  it("should return true for a full URL with http", () => {
    expect(testFqdn("http://example.com")).toBe(true);
  });

  it("should return true for a full URL with https", () => {
    expect(testFqdn("https://example.com")).toBe(true);
  });

  it("should return false for a relative URL", () => {
    expect(testFqdn("/relative-path")).toBe(false);
  });

  it("should return false for a string that is only string", () => {
    expect(testFqdn("invalid-url")).toBe(false);
  });

  it("should return false for an empty string", () => {
    expect(testFqdn("")).toBe(false);
  });
});
