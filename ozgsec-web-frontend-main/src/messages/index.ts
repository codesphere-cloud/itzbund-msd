import {
  AccessiblityInspectionType,
  CertificateInspectionType,
  ContentInspectionType,
  CookieInspectionType,
  DomainInspectionType,
  HeaderInspectionType,
  HttpInspectionType,
  InspectionType,
  NetworkInspectionType,
  OrganizationalInspectionType,
  TLSInspectionType,
} from "../scanner/scans";
import { FeatureFlag, ISarifResponse } from "../types";
import { DTO } from "../utils/server";
import { getDeprecatedTLSDeactivatedReportMessage } from "./deprecatedTLSDeactivated";
import { getDNSSecReportMessage } from "./dnsSec";
import { getHSTSReportMessage } from "./hsts";
import { getHttpMessage } from "./http";
import { getMatchesHostnameMessage } from "./matchesHostname";
import { getProvidesEnglishWebsiteVersionMessage } from "./providesEnglishWebsiteVersion";
import { getResponsibleDisclosureReportMessage } from "./responsibleDisclosure";
import getRPKIReportMessage from "./rpki";
import { getTLSv1_3ReportMessage } from "./tlsv1_3";
import { getValidCertificateMessage } from "./validCertificate";

export const messages = {
  [OrganizationalInspectionType.ResponsibleDisclosure]:
    getResponsibleDisclosureReportMessage,
  [TLSInspectionType.TLSv1_3]: getTLSv1_3ReportMessage,
  [TLSInspectionType.DeprecatedTLSDeactivated]:
    getDeprecatedTLSDeactivatedReportMessage,
  [HeaderInspectionType.HSTS]: getHSTSReportMessage,
  [DomainInspectionType.DNSSec]: getDNSSecReportMessage,
  [NetworkInspectionType.RPKI]: getRPKIReportMessage,
  [CertificateInspectionType.MatchesHostname]: getMatchesHostnameMessage,
  [CertificateInspectionType.ValidCertificate]: getValidCertificateMessage,
  [HttpInspectionType.HTTP]: getHttpMessage,

  [AccessiblityInspectionType.ProvidesEnglishWebsiteVersion]:
    getProvidesEnglishWebsiteVersionMessage,
};

export const titleMapper = {
  [HttpInspectionType.HTTP]: "HTTP",
  [HttpInspectionType.HTTP308]: "HTTP moved permanently",
  [HttpInspectionType.HTTPRedirectsToHttps]: "HTTP Weiterleitung zu HTTPS",
  [TLSInspectionType.TLSv1_2]: "TLS 1.2",
  [TLSInspectionType.TLSv1_3]: "TLS 1.3",
  [TLSInspectionType.DeprecatedTLSDeactivated]:
    "Veraltetes TLS/ SSL deaktiviert",
  [TLSInspectionType.StrongKeyExchange]: "Strong-Key-Exchange",
  [TLSInspectionType.StrongCipherSuites]: "Strong-Cipher-Suites",
  [CertificateInspectionType.ValidCertificate]: "Gültiges Zertifikat",
  [CertificateInspectionType.StrongPrivateKey]: "Starker-Private-Key",
  [CertificateInspectionType.StrongSignatureAlgorithm]:
    "Starker Signatur Algorithmus",
  [CertificateInspectionType.MatchesHostname]:
    "Hostname Übereinstimmung im Zertifikat",
  [CertificateInspectionType.NotRevoked]:
    "Zertifikat wurde nicht zurückgerufen",
  [CertificateInspectionType.CertificateTransparency]: "Zertifikattransparenz",
  [CertificateInspectionType.ValidCertificateChain]: "Gültige Zertifikatskette",
  [CookieInspectionType.SecureSessionCookies]: "Sichere Session Cookies",
  [NetworkInspectionType.IPv6]: "IPv6",
  [NetworkInspectionType.RPKI]: "RPKI",
  [DomainInspectionType.DNSSec]: "DNSSEC",
  [DomainInspectionType.CAA]: "CAA",
  [DomainInspectionType.DANE]: "DANE",
  [DomainInspectionType.DKIM]: "DKIM",
  [DomainInspectionType.DMARC]: "DMARC",
  [DomainInspectionType.SPF]: "SPF",
  [DomainInspectionType.STARTTLS]: "STARTTLS",
  [OrganizationalInspectionType.ResponsibleDisclosure]:
    "Responsible Disclosure",
  [ContentInspectionType.SubResourceIntegrity]: "Sub Resource Integrity",
  [ContentInspectionType.NoMixedContent]: "Kein Mixed Content",
  [HeaderInspectionType.HTTPS]: "HTTPS",
  [HeaderInspectionType.HSTS]: "HSTS",
  [HeaderInspectionType.HSTSPreloaded]: "HSTS Preloaded",
  [HeaderInspectionType.ContentSecurityPolicy]: "Content Security Policy",
  [HeaderInspectionType.XFrameOptions]: "X-Frame-Options",
  [HeaderInspectionType.XSSProtection]: "X-XSS-Protection",
  [HeaderInspectionType.ContentTypeOptions]: "Content-Type-Options",

  [AccessiblityInspectionType.ProvidesEnglishWebsiteVersion]:
    "Englische Website-Version",
};

export const descriptionMapper: { [key in InspectionType]: string } = {
  [OrganizationalInspectionType.ResponsibleDisclosure]:
    "Maßnahme zur Meldung von Schwachstellen vor Veröffentlichung",
  [HttpInspectionType.HTTP]: "",
  [HttpInspectionType.HTTP308]: "",
  [HttpInspectionType.HTTPRedirectsToHttps]: "",
  [TLSInspectionType.TLSv1_2]: "",
  [TLSInspectionType.TLSv1_3]:
    "Aktuelle Verschlüsselung der Kommunikation zwischen Bürgerinnen, Bürgern und OZG-Dienst",
  [TLSInspectionType.DeprecatedTLSDeactivated]:
    "Veraltete Verschlüsselung deaktivieren",
  [TLSInspectionType.StrongKeyExchange]: "",
  [TLSInspectionType.StrongCipherSuites]: "",
  [CertificateInspectionType.ValidCertificate]: "",
  [CertificateInspectionType.StrongPrivateKey]: "",
  [CertificateInspectionType.StrongSignatureAlgorithm]: "",
  [CertificateInspectionType.MatchesHostname]: "",
  [CertificateInspectionType.NotRevoked]: "",
  [CertificateInspectionType.CertificateTransparency]: "",
  [CertificateInspectionType.ValidCertificateChain]: "",
  [CookieInspectionType.SecureSessionCookies]: "",
  [NetworkInspectionType.IPv6]: "",
  [NetworkInspectionType.RPKI]:
    "Schutz vor nicht autorisierter Umleitung von Datenverkehr",
  [DomainInspectionType.DNSSec]:
    "Sichere Verknüpfung von Internetadresse und Serveradresse",
  [DomainInspectionType.DANE]: "",
  [DomainInspectionType.DKIM]: "",
  [DomainInspectionType.DMARC]: "",
  [DomainInspectionType.SPF]: "",
  [DomainInspectionType.STARTTLS]: "",
  [DomainInspectionType.CAA]: "",
  [ContentInspectionType.SubResourceIntegrity]: "",
  [ContentInspectionType.NoMixedContent]: "",
  [HeaderInspectionType.HTTPS]: "",
  [HeaderInspectionType.HSTS]:
    "Sicherstellung verschlüsselter Kommunikation zwischen Bürgerinnen, Bürgern und OZG-Dienst",
  [HeaderInspectionType.HSTSPreloaded]: "",
  [HeaderInspectionType.ContentSecurityPolicy]: "",
  [HeaderInspectionType.XFrameOptions]: "",
  [HeaderInspectionType.XSSProtection]: "",
  [HeaderInspectionType.ContentTypeOptions]: "",

  [AccessiblityInspectionType.ProvidesEnglishWebsiteVersion]:
    "Bereitstellung einer internationalen Version der Website",
};

export const featureFlagMapper: { [key in FeatureFlag]: string } = {
  [FeatureFlag.collections]: "Domain-Gruppen",
};

export const getCheckDescription = (
  report: DTO<ISarifResponse> | null,
  key: keyof typeof messages,
): string => {
  return messages[key](report) ?? "";
};
