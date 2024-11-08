export enum AccessiblityInspectionType {
  ProvidesEnglishWebsiteVersion = "providesEnglishWebsiteVersion",
}

export enum ContentInspectionType {
  SubResourceIntegrity = "subResourceIntegrity",
  NoMixedContent = "noMixedContent",
}

export enum OrganizationalInspectionType {
  ResponsibleDisclosure = "responsibleDisclosure",
}

export enum DomainInspectionType {
  DNSSec = "dnsSec",
  CAA = "caa",

  DKIM = "dkim",
  SPF = "spf",
  DMARC = "dmarc",
  STARTTLS = "starttls",
  DANE = "dane",
}

export enum NetworkInspectionType {
  IPv6 = "ipv6",
  RPKI = "rpki",
}

export enum HttpInspectionType {
  HTTP = "http",
  // permanent redirect to https.
  HTTP308 = "http308",
  // redirect to https.
  HTTPRedirectsToHttps = "httpRedirectsToHttps",
}

export enum HeaderInspectionType {
  HTTPS = "https",
  HSTS = "hsts",
  HSTSPreloaded = "hstsPreloaded",
  ContentSecurityPolicy = "contentSecurityPolicy",
  XFrameOptions = "xFrameOptions",
  XSSProtection = "xssProtection",
  ContentTypeOptions = "contentTypeOptions",
}

export enum CookieInspectionType {
  SecureSessionCookies = "secureSessionCookies",
}
export enum TLSInspectionType {
  TLSv1_2 = "tlsv1_2",
  TLSv1_3 = "tlsv1_3",
  // make sure, that TLS v.1.1 and older is not supported
  DeprecatedTLSDeactivated = "deprecatedTLSDeactivated",
  // string Key-Exchange (min. 2048 bit for DHE; min. 256 bit for
  // prefer ECDHE
  StrongKeyExchange = "strongKeyExchange",
  StrongCipherSuites = "strongCipherSuites",
}

export enum CertificateInspectionType {
  ValidCertificate = "validCertificate",
  // EC min. 256 bit, RSA min. 2048 bit
  StrongPrivateKey = "strongPrivateKey",
  StrongSignatureAlgorithm = "strongSignatureAlgorithm",
  MatchesHostname = "matchesHostname",
  NotRevoked = "notRevoked",
  CertificateTransparency = "certificateTransparency",
  ValidCertificateChain = "validCertificateChain",
}

export type InspectionType =
  | HttpInspectionType
  | TLSInspectionType
  | CertificateInspectionType
  | CookieInspectionType
  | NetworkInspectionType
  | DomainInspectionType
  | OrganizationalInspectionType
  | ContentInspectionType
  | HeaderInspectionType
  | AccessiblityInspectionType;

export const InspectionTypeEnum = {
  ...HttpInspectionType,
  ...TLSInspectionType,
  ...CertificateInspectionType,
  ...CookieInspectionType,
  ...NetworkInspectionType,
  ...DomainInspectionType,
  ...OrganizationalInspectionType,
  ...ContentInspectionType,
  ...HeaderInspectionType,

  ...AccessiblityInspectionType,
};
export type InspectResultDTO =
  | SuccessInspectResultDTO
  | ErrorInspectResultDTO
  | UnknownInspectResultDTO;

export interface SuccessInspectResultDTO {
  didPass: true;
  actualValue: Record<string, any>;
  errors?: string[];
  recommendations?: string[];
}

export interface ErrorInspectResultDTO {
  didPass: false;
  actualValue: Record<string, any>;
  errors?: string[];
  recommendations?: string[];
}

export interface UnknownInspectResultDTO {
  didPass: null;
  actualValue: {
    error: {
      code: string;
      message: string;
    };
  };
  errors?: string[];
  recommendations?: string[];
}
