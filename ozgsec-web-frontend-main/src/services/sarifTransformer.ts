import { InspectionType, InspectResultDTO } from "../scanner/scans";
import {
  DetailsJSON,
  ISarifResponse,
  ISarifScanSuccessResponse,
} from "../types";
import { DTO } from "../utils/server";

// can be removed after the migration to the sarif format is done
// those will be provided by the scanner anyways.
export const sarifRules = [
  {
    fullDescription: {
      text: "Checks if all session cookies are secure and http only. The check inspects the Set-Cookie Header. If Expires attribute is set to 0, the cookie is NOT considered a session cookie.",
    },
    id: "secureSessionCookies",
    name: "Secure Session Cookies",
  },
  {
    fullDescription: {
      text: "Checks if the domain supports CAA. RFC8659 (https://www.rfc-editor.org/rfc/rfc8659.html).",
    },
    id: "caa",
    name: "CAA",
  },
  {
    fullDescription: {
      text: "Strong key exchange algorithms are used",
    },
    id: "strongKeyExchange",
    name: "Strong key exchange",
  },
  {
    fullDescription: {
      text: "Checks if the server responds the HTTP-GET request with a 308 (Permanent Redirect) status code.",
    },
    id: "http308",
    name: "HTTP 308",
  },
  {
    fullDescription: {
      text: "Checks if the certificate is not revoked. The check is conform to RFC5280 (https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2.6)",
    },
    id: "notRevoked",
    name: "Certificate is not revoked",
  },
  {
    fullDescription: {
      text: "Checks if the certificate is not signed using a weak signature algorithm. The check is conform to https://developer.mozilla.org/en-US/docs/Web/Security/Weak_Signature_Algorithm",
    },
    id: "strongSignatureAlgorithm",
    name: "Certificate is not signed using a weak signature algorithm",
  },
  {
    fullDescription: {
      text: "Checks if Subresource Integrity (SRI) (https://www.w3.org/TR/SRI/) integrity is used on the webpage.",
    },
    id: "subResourceIntegrity",
    name: "Subresource Integrity",
  },
  {
    fullDescription: {
      text: "Checks if the website has HSTS enabled. Max-Age is required, includeSubDomains recommended. RFC6797 (https://www.rfc-editor.org/rfc/rfc6797).",
    },
    id: "hsts",
    name: "HSTS",
  },
  {
    fullDescription: {
      text: "Checks if the website HSTS-Header enabled preloading. RFC6797 (https://www.rfc-editor.org/rfc/rfc6797).",
    },
    id: "hstsPreloaded",
    name: "HSTS Preloaded",
  },
  {
    fullDescription: {
      text: "Checks if the website has a Content Security Policy (CSP) enabled. The Check does not validate the configuration since there is no standard. The check adds recommendations if the default-src is not set to 'self' and if script-src, style-src or img-src are missing.",
    },
    id: "contentSecurityPolicy",
    name: "Content Security Policy",
  },
  {
    fullDescription: {
      text: "Checks if the server responds to HTTP requests. If the server responds with a 5xx status code, the check is considered a failure.",
    },
    id: "http",
    name: "HTTP",
  },
  {
    fullDescription: {
      text: "Checks, if strong cipher suites are used during the TLS handshake. As Strong cipher suites we consider the recommended cipher suites from mozilla: https://wiki.mozilla.org/Security/Server_Side_TLS",
    },
    id: "strongCipherSuites",
    name: "Strong cipher suites",
  },
  {
    fullDescription: {
      text: "Checks if the certificate uses certificate transparency. RFC6962 (https://www.rfc-editor.org/rfc/rfc6962) defines a certificate transparency log as a log which contains all certificates which are issued by a CA. This check does not check if the certificate is in the log, but if the certificate contains the certificate transparency extension, signed certificate timestamps or a OCSP Response.",
    },
    id: "certificateTransparency",
    name: "Certificate Transparency",
  },
  {
    fullDescription: {
      text: "Checks if there is mixed content on the webpage (https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content).",
    },
    id: "noMixedContent",
    name: "No Mixed Content",
  },
  {
    fullDescription: {
      text: "Checks if the website has X-Frame-Options enabled. DENY or SAMEORIGIN are both valid configuration. RFC7034 (https://www.rfc-editor.org/rfc/rfc7034).",
    },
    id: "xFrameOptions",
    name: "X-Frame-Options",
  },
  {
    fullDescription: {
      text: "Checks if the website has X-Content-Type-Options enabled. The Value needs to be set to 'nosniff'.",
    },
    id: "contentTypeOptions",
    name: "X-Content-Type-Options",
  },
  {
    fullDescription: {
      text: "Deprecated TLS protocols (SSLv3, TLSv1.0, TLSv1.1) are deactivated",
    },
    id: "deprecatedTLSDeactivated",
    name: "Deprecated TLS deactivated",
  },
  {
    fullDescription: {
      text: "Checks if the target supports RPKI. If the target supports RPKI, it checks if the RPKI status is valid for all derived prefixes. If a domain has multiple IP addresses, the check is considered a success if all IP addresses have a valid RPKI status.",
    },
    id: "rpki",
    name: "RPKI",
  },
  {
    fullDescription: {
      text: "TLS 1.3 is supported",
    },
    id: "tlsv1_3",
    name: "TLS 1.3 supported",
  },
  {
    fullDescription: {
      text: "Checks if the certificate of a website is valid. A certificate is considered valid if it is not expired and if it is yet valid.",
    },
    id: "validCertificate",
    name: "Valid Certificate",
  },
  {
    fullDescription: {
      text: "Checks if the certificate chain is valid. The check is conform to RFC5280 (https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)",
    },
    id: "validCertificateChain",
    name: "Signing-Chain of the certificate is valid",
  },
  {
    fullDescription: {
      text: "Checks if the domain supports DNSSEC. RFC9364 (https://www.rfc-editor.org/rfc/rfc9364).",
    },
    id: "dnsSec",
    name: "DNSSEC",
  },
  {
    fullDescription: {
      text: "Checks if the website has X-XSS-Protection enabled. Needs to have a value of 1 and the mode needs to be set to 'block'. RFC7034 (https://www.rfc-editor.org/rfc/rfc7034).",
    },
    id: "xssProtection",
    name: "X-XSS-Protection",
  },
  {
    fullDescription: {
      text: "Checks, if the website redirects to an https site, if an http request is send to it.",
    },
    id: "httpRedirectsToHttps",
    name: "HTTP redirects to HTTPS",
  },
  {
    fullDescription: {
      text: "Checks if the target supports IPv6.",
    },
    id: "ipv6",
    name: "IPv6",
  },
  {
    fullDescription: {
      text: "TLS 1.2 is supported",
    },
    id: "tlsv1_2",
    name: "TLS 1.2 supported",
  },
  {
    fullDescription: {
      text: "Checks if the certificate matches the hostname of the website.",
    },
    id: "matchesHostname",
    name: "Certificate matches hostname of the website",
  },
  {
    fullDescription: {
      text: "Checks if the certificate is signed using a strong private key. A strong private key is a private RSA key with a bit length of at least 2048 or a DSA key.",
    },
    id: "strongPrivateKey",
    name: "Certificate is signed using a strong private key",
  },
  {
    fullDescription: {
      text: "Checks if the website is served over HTTPS. It will will follow redirects to HTTPS.",
    },
    id: "https",
    name: "HTTPS",
  },
  {
    fullDescription: {
      text: "Checks, if the file /.well-known/security.txt is present, served over https, is served as a text/plain file,  and if it contains the required fields. The required fields are: Contact, Expires. The recommended fields are: Encryption, Canonical, Preferred-Languages. The file is also checked for a PGP signature.",
    },
    id: "responsibleDisclosure",
    name: "Responsible Disclosure",
  },
];

export const didPass2Kind = (
  didPass: boolean | null,
): "notApplicable" | "pass" | "fail" => {
  if (didPass === null) {
    return "notApplicable";
  }
  if (didPass === true) {
    return "pass";
  }
  return "fail";
};

export const kind2DidPass = (
  kind: "notApplicable" | "pass" | "fail" | undefined,
): boolean | null => {
  if (kind === undefined) {
    return null;
  }
  if (kind === "notApplicable") {
    return null;
  }
  if (kind === "pass") {
    return true;
  }
  return false;
};

export const startTimeOfResponse = (sarif: ISarifResponse): Date => {
  return new Date(sarif.runs[0].invocations[0].startTimeUtc);
};

export const endTimeOfResponse = (sarif: ISarifResponse): Date => {
  return new Date(sarif.runs[0].invocations[0].endTimeUtc);
};

export const getTargetFromResponse = (sarif: ISarifResponse): string => {
  return sarif.runs[0].properties.target;
};

export function getSUTFromResponse(
  sarif: ISarifResponse | undefined | null,
): string | undefined {
  if (!sarif) {
    return undefined;
  }
  return sarif.runs[0].properties.sut;
}
export const transformSarifToDeprecatedReportingSchema = (
  input: DTO<ISarifScanSuccessResponse>,
): DTO<DetailsJSON> => {
  return input.runs[0].results.reduce(
    (acc, curr) => {
      acc[curr.ruleId] = {
        didPass: kind2DidPass(curr.kind),
        errors: curr.properties.errorIds,
        recommendations: curr.properties.recommendationIds,
        actualValue: curr.properties.actualValue,
      };
      return acc;
    },
    {
      sut: input.runs[0].properties.sut,
    } as DTO<DetailsJSON>,
  );
};

export const transformDeprecatedReportingSchemaToSarif = (
  input: DTO<DetailsJSON> | DTO<ISarifScanSuccessResponse>,
): DTO<ISarifScanSuccessResponse> => {
  // check if the input is already in the new format
  if ("runs" in input) {
    return input;
  }
  // now transform it.
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ozgsec-scanner",
            properties: {
              scannerIp: "0.0.0.0",
            },
            rules: sarifRules,
          },
        },
        results: Object.entries(input)
          .filter(
            (el): el is [InspectionType, InspectResultDTO] => el[0] !== "sut",
          )
          .map(([k, v]) => {
            return {
              kind: didPass2Kind(v.didPass),
              ruleId: k,
              ruleIndex: sarifRules.findIndex((el) => el.id === k),
              message: {
                text: v.didPass === null ? v.actualValue?.error?.message : "",
              },
              properties: {
                errorIds: v.errors ?? [],
                recommendationIds: v.recommendations ?? [],
                actualValue: v.actualValue,
              },
            };
          }),
        invocations: [
          {
            executionSuccessful: true, // it has to be a success, otherwise it would not be in the database
            exitCode: 0,
            exitCodeDescription: "success",
            startTimeUtc: new Date().toUTCString(),
            endTimeUtc: new Date().toUTCString(),
          },
        ],
        properties: {
          ipAddress: "0.0.0.0", // this is just a dummy - it was not saved in the old format inside
          sut: input.sut,
          target: input.sut,
        },
      },
    ],
  };
};
