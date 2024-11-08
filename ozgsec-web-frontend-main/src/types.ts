import { Target } from "@prisma/client";
import { InspectionType, InspectResultDTO } from "./scanner/scans";
import {
  Invocation,
  ReportingDescriptor,
  Result,
  Run,
  StaticAnalysisResultsFormatSARIFVersion210Rtm4JSONSchema,
} from "./sarif";
import { DTO } from "./utils/server";

export enum FeatureFlag {
  collections = "collections",
}
export interface IDashboard {
  historicalData: CollectionStatMap;
  totals: {
    uniqueTargets: number;
  };
}

export interface ChartData {
  data: {
    [key in InspectionType]: number;
  };
  totalCount: number;
}

export type CollectionStatMap = {
  [collectionId: number]: CollectionStat | undefined;
};
export type SingleCollectionStatMap = {
  [collectionId: number]: SingleCollectionStat | undefined;
};

export interface CollectionStat {
  series: Array<ChartData & { date: number }>;
  title: string;
  color: string;
}

export interface SingleCollectionStat {
  singleStat: ChartData & { date: number };
  title: string;
  color: string;
}

export interface INetworkPatchDTO {
  comment?: string;
}

export type IUserPutDTO = ICreateUserDTO & { id: string };

export type IIpLookupReportMsg = {
  results: { [ip: string]: string[] };
} & {
  cidr: string;
  requestId: string;
};

export interface IIpLookupRequestMsg {
  cidr: string;
  requestId: string;
  sendProgress?: boolean; // defaults to false
}

export interface IIpLookupProgressUpdateMsg {
  requestId: string;
  cidr: string;
  queued: number;
  processed: number;
  results: { [ip: string]: string[] };
}

export type IIpLookupProgressUpdateDTO = Omit<
  IIpLookupProgressUpdateMsg,
  "results"
> & { results: Array<{ domain: string; ip: string }> };

export type IIpLookupReportDTO = Omit<IIpLookupReportMsg, "results"> & {
  results: Array<{ domain: string; ip: string }>;
};

export enum TargetType {
  all = "all",
  reachable = "reachable",
  unreachable = "unreachable",
}

export interface ISession {
  user: {
    name: string;
    username: string;
    id: string;
    // identifies a guest
    collectionId?: number;
  };
  realmAccess: {
    roles: string[];
  };
  error?: string;
}

export interface AccessAndRefreshToken {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  expiresAt: number;
}
export interface IToken extends ISession, AccessAndRefreshToken {}

export interface ICreateUserDTO {
  username: string;
  featureFlags: Record<FeatureFlag, boolean>;
}

/**
 * @deprecated The scanner will provide new reports in sarif format.
 */
export type IScanSuccessResponse = {
  result: Partial<{
    [key in InspectionType]: InspectResultDTO;
  }>;
  target: string;
  ipAddress: string;
  duration: number;
  timestamp: number;
  sut: string;
};

export type ErrorCode = "could_not_resolve_hostname" | "could_not_parse_url"; // those strings are defined in the best-practices-scanner

/**
 * @deprecated The scanner will provide new reports in sarif format.
 */
export type IScanErrorResponse = {
  target: string;
  timestamp: number;
  ipAddress: string;
  duration: number;
  result: { error: { message: string; code: ErrorCode } };
};

export type Kind = "pass" | "fail" | "notApplicable";

export type ISarifScanSuccessResponse = DTO<
  StaticAnalysisResultsFormatSARIFVersion210Rtm4JSONSchema & {
    runs: Array<
      Omit<Run, "results"> & {
        results: Array<
          Result & {
            ruleId: InspectionType;
            message: {
              text: string;
            };
            kind: "pass" | "notApplicable" | "fail";
            properties: {
              errorIds: string[];
              recommendationIds: string[];
              actualValue: any;
            };
          }
        >;
        invocations: Array<
          Invocation & {
            exitCode: 0;
            executionSuccessful: true;
            startTimeUtc: string;
            endTimeUtc: string;
          }
        >;
        tool: {
          driver: {
            properties: {
              scannerIp: string;
            };
            rules: ReportingDescriptor[];
          };
        };
        properties: {
          target: string;
          sut: string;
          ipAddress: string;
        };
      }
    >;
  }
>;

export type ISarifScanErrorResponse = DTO<
  StaticAnalysisResultsFormatSARIFVersion210Rtm4JSONSchema & {
    runs: Array<
      Omit<Run, "results"> & {
        results: []; // will always be empty if the scan failed
        invocations: Array<
          Invocation & {
            exitCode: 1;
            executionSuccessful: false;
            startTimeUtc: string;
            endTimeUtc: string;
          }
        >;
        tool: {
          driver: {
            properties: {
              scannerIp: string;
            };
            rules: ReportingDescriptor[];
          };
        };
        properties: {
          target: string;
          sut: string;
          ipAddress: string;
        };
      }
    >;
  }
>;

export type ISarifResponse =
  | ISarifScanErrorResponse
  | ISarifScanSuccessResponse;

export type IScanResponse = IScanErrorResponse | IScanSuccessResponse;

export interface TestAmount {
  passed: number;
  total: number;
}

export interface PaginateRequest {
  page: number;
  pageSize: number;
}

export interface PaginateResult<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
}

export type WithoutId<T> = Omit<T, "id">;
export interface IKcUser {
  id: string;
  createdTimestamp: number;
  username: string;
  enabled: boolean;
  totp: boolean;
  emailVerified: boolean;
  firstName: string;
  lastName: string;
  attributes?: { role: string[] };
  notBefore: number;
}

export type DetailsJSON = IScanSuccessResponse["result"] & { sut: string };

export type DetailedTarget = Omit<
  Target,
  "lastScan" | "details" | "createdAt"
> & {
  details: ISarifResponse | null;
  lastScan: number;
  createdAt: string;
};

export interface Guest {
  // same as share link secret
  id: string;
  collectionId: number;
}

export interface UriDiff {
  uri: string;
  diff: {
    [key in InspectionType]?: {
      was: boolean | null;
      now: boolean | null;
    };
  };
}

export interface Diffs {
  uriDiffs: UriDiff[];
  start: number;
  end: number;
}
