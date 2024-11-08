import {
  FeatureFlag,
  Guest,
  IIpLookupProgressUpdateMsg,
  IIpLookupReportDTO,
  IIpLookupReportMsg,
  ISarifResponse,
  ISarifScanErrorResponse,
  ISarifScanSuccessResponse,
  ISession,
  WithoutId,
} from "../types";

import { Network, User } from "@prisma/client";

import ip from "ip";
import { toUnicode } from "punycode/";
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
import { DTO } from "./server";
import { isValidHostname, isValidIp, isValidMask } from "./validator";

export const once = <T extends (...args: any) => any>(fn: T): T => {
  let executed = false;
  let result: ReturnType<T>;
  return (async (...args: any) => {
    if (executed) {
      return result;
    }
    executed = true;
    result = await fn(...args);
    return result;
  }) as T;
};

export const serverOnly = <T>(fn: () => T): T | null => {
  if (typeof window === "undefined") {
    return fn();
  }
  return null;
};

export const zip = <T, U>(arr1: T[], arr2: U[]): [T, U][] => {
  return arr1.map((el, i) => [el, arr2[i]]);
};

export const clientOnly = <T>(fn: () => T): T | null => {
  if (typeof window !== "undefined") {
    return fn();
  }
  return null;
};

export const getUnicodeHostnameFromUri = (hostname: string) => {
  return toUnicode(getHostnameFromUri(hostname));
};

export const isProgressMessage = (
  message: Record<string, any>,
): message is IIpLookupProgressUpdateMsg => {
  return "queued" in message;
};

export const transformIpLookupMsg2DTO = (
  msg: IIpLookupReportMsg,
): IIpLookupReportDTO => {
  return {
    ...msg,
    results: Object.entries(msg.results)
      .map(([ip, domains]) =>
        domains.map((domain) => ({
          ip,
          domain,
        })),
      )
      .flat(),
  };
};

export const splitLineBreak = (str: string): string[] => {
  return str.split(/\r?\n|\r|\n/g).map((s) => s.trim());
};

export const limitStringValues = <T>(obj: T, charLimit = 255): T => {
  if (obj === null || obj === undefined) {
    return obj;
  }
  if (obj instanceof Array) {
    return obj.map((el) => limitStringValues(el, charLimit)) as any;
  }
  if (typeof obj === "string") {
    return obj.slice(0, charLimit) as any;
  }
  if (typeof obj === "object") {
    return Object.fromEntries(
      Object.entries(obj).map(([key, value]) => {
        return [key, limitStringValues(value, charLimit)];
      }),
    ) as any;
  }
  return obj;
};

export const hash = async (stringToHash: string) => {
  const utf8 = new TextEncoder().encode(stringToHash);
  const hashBuffer = await crypto.subtle.digest("SHA-256", utf8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((bytes) => bytes.toString(16).padStart(2, "0")).join("");
};

export const getUriWithHashedHostname = async (
  uri: string,
): Promise<string> => {
  const hashedHostname = await hash(getHostnameFromUri(uri));
  const urlPath = getPathFromUri(uri);
  return `${hashedHostname}${urlPath.length > 1 ? urlPath : ""}`;
};

export const getPathFromUri = (uri: string): string => {
  const urlWithHttp = uri.startsWith("http") ? uri : `http://${uri}`;
  const path = new URL(urlWithHttp).pathname;
  return path === "/" ? "" : path;
};

export const getHostnameFromUri = (uri: string): string => {
  if (uri.startsWith("http")) {
    const url = new URL(uri);
    return url.hostname;
  }
  const url = new URL(`http://${uri}`);
  return url.hostname;
};

export const replaceNullWithZero = <T>(obj: T): T => {
  if (obj === null) {
    return 0 as T;
  }
  if (obj instanceof Array) {
    return obj.map((el) => replaceNullWithZero(el)) as any;
  }
  if (typeof obj === "object") {
    return Object.fromEntries(
      Object.entries(obj).map(([key, value]) => {
        return [key, replaceNullWithZero(value)];
      }),
    ) as T;
  }
  return obj;
};
export const isAdmin = (session: ISession | null | undefined): boolean => {
  if (!session || !session.realmAccess) {
    return false;
  }
  return Boolean(session?.realmAccess?.roles.includes("admin"));
};

export const isFeatureEnabled = (feature: FeatureFlag, user: User): boolean => {
  if (!user.featureFlags || typeof user.featureFlags !== "object") {
    return false;
  }

  return Boolean((user.featureFlags as Record<FeatureFlag, boolean>)[feature]);
};

export const promise2Boolean = async (promise: Promise<any>) => {
  try {
    await promise;
    return true;
  } catch {
    return false;
  }
};

export const wait = (delayMS: number) => {
  return new Promise<void>((resolve) => setTimeout(resolve, delayMS));
};

export const timeout = async <T>(
  promise: Promise<T>,
  timeoutMS = 3_000,
): Promise<T> => {
  const result = await Promise.race([promise, wait(timeoutMS)]);
  if (!result) {
    throw new Error("timeout");
  }
  return result;
};

/**
 * @param providedValue Any value which should be sanitized as a FQDN
 * @returns The sanitized FQDN or null if the provided value is not a string
 */
export const sanitizeURI = (providedValue: any): string | null => {
  if (typeof providedValue !== "string" || !providedValue.includes(".")) {
    return null;
  }
  // remove blank characters
  providedValue = providedValue.trim();

  // add a protocol to the provided value, so that the URL constructor
  // can parse it correctly
  const url = new URL(
    providedValue.startsWith("https://") || providedValue.startsWith("http://")
      ? providedValue
      : `https://${providedValue}`,
  );

  url.hostname = url.hostname.toLowerCase();

  if (!isValidHostname(url.hostname)) {
    return null;
  }

  if (url.pathname !== "/") {
    return toUnicode(
      url.port
        ? `${url.hostname}:${url.port}${url.pathname}`
        : url.hostname + url.pathname,
    );
  }

  // make sure to keep the port if provided
  return url.port ? `${url.hostname}:${url.port}` : url.hostname;
};

export const classNames = (
  ...args: Array<string | boolean | undefined | null>
): string => {
  return args.filter(Boolean).join(" ");
};

export const parseNetwork = (cidr: string): WithoutId<DTO<Network>> => {
  const subnet = ip.cidrSubnet(cidr);

  return {
    prefixLength: subnet.subnetMaskLength,
    networkAddress: subnet.networkAddress,
    cidr,
    comment: null,
    startAddressNumber: ip.toLong(subnet.firstAddress),
    endAddressNumber: ip.toLong(subnet.lastAddress),
  } as WithoutId<DTO<Network>>;
};

export const parseNetworkString = (networks: string | string[]): string[] => {
  // parse the networks - they are line separated
  const networksArray =
    networks instanceof Array ? networks : networks.trim().split("\n");
  // check if each network is in cidr notation.

  const networksValid = networksArray.every((network) => {
    const [ip, mask] = network.split("/");
    if (ip === undefined || mask === undefined) {
      return false;
    }
    const ipValid = isValidIp(ip);
    const maskValid = isValidMask(mask);
    return ipValid && maskValid;
  });
  if (!networksValid) {
    throw new Error("Bitte trage gültige Netzwerke ein.");
  }
  return networksArray;
};

export const isScanError = (
  response: ISarifResponse,
): response is ISarifScanErrorResponse => {
  return response.runs[0].invocations[0].exitCode !== 0;
};

export const isScanSuccess = (
  response: ISarifResponse,
): response is ISarifScanSuccessResponse => {
  return !isScanError(response);
};

export const linkMapper: { [key in InspectionType]: string } = {
  [HttpInspectionType.HTTP]: "",
  [HttpInspectionType.HTTP308]: "",
  [HttpInspectionType.HTTPRedirectsToHttps]: "",
  [TLSInspectionType.TLSv1_2]: "",
  [TLSInspectionType.TLSv1_3]: "/one-pager/TLS1_3-One-Pager.pdf",
  [TLSInspectionType.DeprecatedTLSDeactivated]:
    "/one-pager/TLS1_1_off-One-Pager.pdf",
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
  [NetworkInspectionType.RPKI]: "/one-pager/RPKI-One-Pager.pdf",
  [DomainInspectionType.DNSSec]: "/one-pager/DNSSEC-One-Pager.pdf",
  [DomainInspectionType.CAA]: "",
  [DomainInspectionType.DANE]: "",
  [DomainInspectionType.DKIM]: "",
  [DomainInspectionType.DMARC]: "",
  [DomainInspectionType.SPF]: "",
  [DomainInspectionType.STARTTLS]: "",
  [OrganizationalInspectionType.ResponsibleDisclosure]:
    "/one-pager/Responsible_Disclosure-One-Pager.pdf",
  [ContentInspectionType.SubResourceIntegrity]: "",
  [ContentInspectionType.NoMixedContent]: "",
  [HeaderInspectionType.HTTPS]: "",
  [HeaderInspectionType.HSTS]: "/one-pager/HSTS-One-Pager.pdf",
  [HeaderInspectionType.HSTSPreloaded]: "",
  [HeaderInspectionType.ContentSecurityPolicy]: "",
  [HeaderInspectionType.XFrameOptions]: "",
  [HeaderInspectionType.XSSProtection]: "",
  [HeaderInspectionType.ContentTypeOptions]: "",

  [AccessiblityInspectionType.ProvidesEnglishWebsiteVersion]: "",
};

export type Normalized<T> = {
  [key: string]: T;
};

export const normalizeToMap = <T extends object, Key extends keyof T>(
  arr: T[],
  identifier: Key,
) => {
  return arr.reduce((acc, cur) => {
    return {
      ...acc,
      [cur[identifier] as string]: cur,
    };
  }, {} as Normalized<T>);
};

export const neverThrow = async <T>(promise: Promise<T>): Promise<T | null> => {
  try {
    return await promise;
  } catch (e) {
    return null;
  }
};

export const defaultOnError = async <T, D>(
  promise: Promise<T>,
  d: D,
): Promise<T | D> => {
  const res = await neverThrow(promise);
  if (res === null) {
    return d;
  }
  return res;
};

export const dateFormat = {
  hour12: false,
  day: "2-digit" as const,
  month: "2-digit" as const,
  year: "2-digit" as const,
};

export const emailRegex = new RegExp(
  /^[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*@[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*$/,
);

export const toGermanDate = (date: Date): string => {
  return date.toLocaleDateString("de-DE", dateFormat);
};

export const devOnly = <T>(fn: () => T): T | null => {
  if (process.env.NEXT_PUBLIC_ENVIRONMENT === "development") {
    return fn();
  }
  return null;
};

export const colors = [
  "#ef4444",
  "#f97316",
  "#f59e0b",
  "#eab308",
  "#84cc16",
  "#22c55e",
  "#10b981",
  "#14b8a6",
  "#06b6d4",
  "#0ea5e9",
  "#3b82f6",
  "#6366f1",
  "#8b5cf6",
  "#a855f7",
  "#d946ef",
];

export const isGuestUser = (user: any): user is Guest => {
  if (!user) {
    return false;
  }
  return "collectionId" in user && user.collectionId !== undefined;
};

export const collectionId = (user: User | Guest): number => {
  if (isGuestUser(user)) {
    return user.collectionId;
  }
  return user.defaultCollectionId;
};

export const testFqdn = (url: string): boolean => {
  const urlPattern: RegExp = /^(https?:\/\/[^\s$.?#].\S*)$/i;
  return urlPattern.test(url);
};
