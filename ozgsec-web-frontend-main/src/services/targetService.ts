import { Prisma, PrismaClient, Target, User } from "@prisma/client";
import { toASCII } from "punycode";
import { InspectionType, InspectionTypeEnum } from "../scanner/scans";
import {
  DetailedTarget,
  Guest,
  ISarifScanErrorResponse,
  PaginateRequest,
  PaginateResult,
  TargetType,
} from "../types";
import { collectionId, getHostnameFromUri } from "../utils/common";
import { DTO, toDTO } from "../utils/server";
import { getLogger } from "./logger";
import { targetCollectionService } from "./targetCollectionService";
import { transformDeprecatedReportingSchemaToSarif } from "./sarifTransformer";

const logger = getLogger(__filename);

const handleNewTarget = async (
  target: { uri: string; queued?: boolean; collectionIds?: Array<number> },
  prisma: PrismaClient,
  connectToUser?: User,
): Promise<Target> => {
  // fetch the last existing report and check if we only need to update that one.
  let payload = {
    uri: target.uri,
    lastScan: null,
    queued: target.queued ?? false,
    hostname: getHostnameFromUri(target.uri),
  };

  const d = await prisma.target.upsert({
    where: {
      uri: payload.uri,
    },
    update: {},
    create: payload,
  });

  if (target.collectionIds) {
    await Promise.all(
      target.collectionIds.map((c) =>
        targetCollectionService.createConnection([payload.uri], c, prisma),
      ),
    );
  }

  if (connectToUser) {
    await targetCollectionService.createConnection(
      [payload.uri],
      connectToUser.defaultCollectionId,
      prisma,
    );
  }

  return d;
};

const handleTargetScanError = async (
  content: ISarifScanErrorResponse,
  prisma: PrismaClient,
) => {
  const startTime = content?.runs[0]?.invocations[0]?.startTimeUtc;
  const lastScan = !!startTime ? new Date(startTime).getTime() : Date.now();
  const targetUri = content?.runs[0]?.properties?.target;
  return prisma.target.upsert({
    where: {
      uri: targetUri,
    },
    update: {
      lastScan,
      queued: false,
      errorCount: {
        increment: 1,
      },
    },
    create: {
      errorCount: 1,
      uri: targetUri,
      lastScan,
      hostname: getHostnameFromUri(targetUri),
    },
  });
};

const translateSortDirection = (
  direction?: string | "1" | "-1",
): "ASC" | "DESC" => {
  if (direction === "-1") {
    return "DESC";
  }
  return "ASC";
};

const inspectionFilter = (filter: {
  [key in InspectionType]?: "0" | "1" | "-1";
}): string => {
  const obj = Object.entries(filter).filter(([key]) =>
    Object.values(InspectionTypeEnum).includes(key as InspectionType),
  );

  if (obj.length === 0) {
    return "";
  }
  return `${obj
    .map(([key, value]) => {
      if (value === "1") {
        return `"${key}" = true`;
      } else if (value === "-1") {
        return `"${key}" = false`;
      } else if (value === "0") {
        return `"${key}" IS NULL`;
      } else {
        return "";
      }
    })
    .filter((s) => s !== "")
    .join(" AND ")}  AND`;
};

const getUserTargetsWithLatestTestResult = async (
  user: User | Guest,
  paginateRequest: PaginateRequest & { search?: string } & {
    sortDirection?: string;
    type?: TargetType;
    collectionIds?: Array<number>;
    reverseUriBeforeSort?: boolean;
  } & {
    [key in InspectionType]?: "0" | "1" | "-1";
  },
  prisma: PrismaClient,
): Promise<PaginateResult<DTO<DetailedTarget>>> => {
  const sqlValues: Array<string | number> = [
    collectionId(user),
    paginateRequest.pageSize,
    paginateRequest.page * paginateRequest.pageSize,
  ];

  if (paginateRequest.search !== undefined && paginateRequest.search !== "") {
    sqlValues.push(toASCII(paginateRequest.search.toLowerCase()));
  }

  // subject to sql injection!!!
  const targets = (await prisma.$queryRawUnsafe(
    `
      SELECT count(*) OVER() AS "totalCount", t.*, lsd.details as details from targets t 
      LEFT JOIN scan_reports sr on t.uri = sr.uri
      LEFT JOIN last_scan_details lsd on t.uri = lsd.uri
      WHERE ${inspectionFilter(paginateRequest)} NOT EXISTS(
          SELECT 1 from scan_reports sr2 where sr.uri = sr2.uri AND sr."createdAt" < sr2."createdAt"
        )
        ${
          paginateRequest.search !== undefined && paginateRequest.search !== ""
            ? "AND t.uri LIKE CONCAT('%', $4, '%')"
            : ""
        }
        AND EXISTS(
            SELECT 1 from target_collections tc where tc.uri = t.uri AND tc."collectionId" = $1
        )
        ${
          paginateRequest.collectionIds !== undefined &&
          paginateRequest.collectionIds.length > 0
            ? `AND EXISTS(
                SELECT 1 from target_collections tc where tc.uri = t.uri AND tc."collectionId" IN (${paginateRequest.collectionIds
                  .filter((id) => !isNaN(id))
                  .join(",")})
            )`
            : ""
        }
        ${
          paginateRequest.type === TargetType.unreachable
            ? 'AND "errorCount" >= 5'
            : paginateRequest.type === TargetType.reachable
              ? 'AND "errorCount" < 5'
              : ""
        }
        ORDER BY 
           ARRAY(
            SELECT ord || val
            FROM unnest(string_to_array(t.hostname, '.')) WITH ORDINALITY AS u(val, ord)
            ORDER BY ord ${
              paginateRequest.reverseUriBeforeSort ? "DESC" : "ASC"
            }
        ) ${translateSortDirection(paginateRequest.sortDirection)}
        LIMIT $2
        OFFSET $3;
`,
    ...sqlValues,
  )) as Array<any>;

  return {
    total: targets.length > 0 ? Number(targets[0].totalCount) : 0,
    page: paginateRequest.page,
    pageSize: paginateRequest.pageSize,
    data: targets
      .map((t) => ({
        ...t,
        details: transformDeprecatedReportingSchemaToSarif(t.details),
      }))
      .map(toDTO),
  };
};

const getTargets2Scan = async (prisma: PrismaClient) => {
  const scanIntervalMinutes = +(process.env.SCAN_INTERVAL_DAYS ?? 1) * 24 * 60;

  // make sure to round - otherwise we might miss some targets since it does two ticks in the same minute even though one tick is at 01 seconds and the other at 59 seconds
  const currentMinute =
    Math.round(Date.now() / 1000 / 60) % scanIntervalMinutes;

  logger.info(
    `selecting: MOD(number + ${currentMinute}, ${scanIntervalMinutes}) = 0`,
  );

  const targets = (await prisma.$queryRaw(Prisma.sql`
  SELECT * from targets where ("lastScan" < ${new Date(
    new Date().getTime() - (scanIntervalMinutes * 60 * 1000) / 2, // look if the last scan is older than half the interval - otherwise since we ping each minute, it might happen, that the lastScanInterval does actually match the current minute so we loose a scan
  ).getTime()} OR "lastScan" IS NULL) AND "queued" = false AND "errorCount" < 5 AND MOD(number + ${currentMinute}, ${scanIntervalMinutes}) = 0 AND exists(SELECT 1 from target_collections tc WHERE tc.uri = targets.uri)`)) as Array<Target>;

  await prisma.target.updateMany({
    where: {
      uri: {
        in: targets.map((d) => d.uri),
      },
    },
    data: {
      queued: true,
    },
  });

  return targets;
};

export const targetService = {
  handleNewTarget,
  handleTargetScanError,
  getUserTargetsWithLatestTestResult,
  getTargets2Scan,
};
