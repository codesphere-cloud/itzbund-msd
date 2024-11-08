/*
  Warnings:

  - You are about to drop the column `CAA` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `CertificateTransparency` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `ContentSecurityPolicy` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `ContentTypeOptions` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `DNSSec` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `HSTS` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `HSTSPreloaded` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `HTTP` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `HTTP308` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `HTTPRedirectsToHttps` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `HTTPS` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `IPv6` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `MatchesHostname` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `NoMixedContent` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `NotRevoked` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `RPKI` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `ResponsibleDisclosure` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `SecureSessionCookies` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `StrongCipherSuites` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `StrongKeyExchange` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `StrongPrivateKey` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `StrongSignatureAlgorithm` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `SubResourceIntegrity` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `TLSv1_1_Deactivated` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `TLSv1_2` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `TLSv1_3` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `ValidCertificate` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `ValidCertificateChain` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `XFrameOptions` on the `scan_reports` table. All the data in the column will be lost.
  - You are about to drop the column `XSSProtection` on the `scan_reports` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "scan_reports" DROP COLUMN "CAA",
DROP COLUMN "CertificateTransparency",
DROP COLUMN "ContentSecurityPolicy",
DROP COLUMN "ContentTypeOptions",
DROP COLUMN "DNSSec",
DROP COLUMN "HSTS",
DROP COLUMN "HSTSPreloaded",
DROP COLUMN "HTTP",
DROP COLUMN "HTTP308",
DROP COLUMN "HTTPRedirectsToHttps",
DROP COLUMN "HTTPS",
DROP COLUMN "IPv6",
DROP COLUMN "MatchesHostname",
DROP COLUMN "NoMixedContent",
DROP COLUMN "NotRevoked",
DROP COLUMN "RPKI",
DROP COLUMN "ResponsibleDisclosure",
DROP COLUMN "SecureSessionCookies",
DROP COLUMN "StrongCipherSuites",
DROP COLUMN "StrongKeyExchange",
DROP COLUMN "StrongPrivateKey",
DROP COLUMN "StrongSignatureAlgorithm",
DROP COLUMN "SubResourceIntegrity",
DROP COLUMN "TLSv1_1_Deactivated",
DROP COLUMN "TLSv1_2",
DROP COLUMN "TLSv1_3",
DROP COLUMN "ValidCertificate",
DROP COLUMN "ValidCertificateChain",
DROP COLUMN "XFrameOptions",
DROP COLUMN "XSSProtection",
ADD COLUMN     "caa" BOOLEAN,
ADD COLUMN     "certificateTransparency" BOOLEAN,
ADD COLUMN     "contentSecurityPolicy" BOOLEAN,
ADD COLUMN     "contentTypeOptions" BOOLEAN,
ADD COLUMN     "dnsSec" BOOLEAN,
ADD COLUMN     "hsts" BOOLEAN,
ADD COLUMN     "hstsPreloaded" BOOLEAN,
ADD COLUMN     "http" BOOLEAN,
ADD COLUMN     "http308" BOOLEAN,
ADD COLUMN     "httpRedirectsToHttps" BOOLEAN,
ADD COLUMN     "https" BOOLEAN,
ADD COLUMN     "ipv6" BOOLEAN,
ADD COLUMN     "matchesHostname" BOOLEAN,
ADD COLUMN     "noMixedContent" BOOLEAN,
ADD COLUMN     "notRevoked" BOOLEAN,
ADD COLUMN     "responsibleDisclosure" BOOLEAN,
ADD COLUMN     "rpki" BOOLEAN,
ADD COLUMN     "secureSessionCookies" BOOLEAN,
ADD COLUMN     "strongCipherSuites" BOOLEAN,
ADD COLUMN     "strongKeyExchange" BOOLEAN,
ADD COLUMN     "strongPrivateKey" BOOLEAN,
ADD COLUMN     "strongSignatureAlgorithm" BOOLEAN,
ADD COLUMN     "subResourceIntegrity" BOOLEAN,
ADD COLUMN     "tlsv1_1_Deactivated" BOOLEAN,
ADD COLUMN     "tlsv1_2" BOOLEAN,
ADD COLUMN     "tlsv1_3" BOOLEAN,
ADD COLUMN     "validCertificate" BOOLEAN,
ADD COLUMN     "validCertificateChain" BOOLEAN,
ADD COLUMN     "xFrameOptions" BOOLEAN,
ADD COLUMN     "xssProtection" BOOLEAN;
