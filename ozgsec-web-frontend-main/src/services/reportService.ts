import { Prisma, PrismaClient, ScanReport } from "@prisma/client";
import { config } from "../config";
import { ScanTargetOptions } from "../scanner/scanService";
import { scanService } from "../scanner/scanner.module";
import { InspectionType, InspectionTypeEnum } from "../scanner/scans";
import {
  DetailedTarget,
  DetailsJSON,
  Diffs,
  ISarifResponse,
  ISarifScanSuccessResponse,
  PaginateRequest,
} from "../types";
import { getHostnameFromUri, isScanSuccess } from "../utils/common";
import { DTO, toDTO } from "../utils/server";
import { getLogger } from "./logger";
import {
  endTimeOfResponse,
  getTargetFromResponse,
  kind2DidPass,
  startTimeOfResponse,
  transformDeprecatedReportingSchemaToSarif,
} from "./sarifTransformer";

const logger = getLogger(__filename);

const didPassEq = (
  didPassA: boolean | null | undefined,
  didPassB: boolean | null | undefined,
) => {
  if (didPassA === didPassB) {
    return true;
  }
  return (
    (didPassA === null && didPassB === undefined) ||
    (didPassA === undefined && didPassB === null)
  );
};
const reportDidChange = (
  lastReport: Omit<ScanReport, "createdAt" | "updatedAt" | "id">,
  newReport: Omit<ScanReport, "createdAt" | "updatedAt" | "id">,
) => {
  return Object.values(InspectionTypeEnum).some((key) => {
    return !didPassEq(lastReport[key], newReport[key]);
  });
};

export const diffReport = (
  lastReport: ScanReport,
  secondLastReport?: ScanReport,
): Record<InspectionType, { was: boolean | null; now: boolean | null }> => {
  return Object.values(InspectionTypeEnum).reduce(
    (acc, key) => {
      if (!secondLastReport) {
        acc[key] = {
          now: lastReport[key],
          was: null,
        };
        return acc;
      }
      if (lastReport[key] === secondLastReport[key]) {
        return acc;
      }
      acc[key] = {
        now: lastReport[key],
        was: secondLastReport[key],
      };
      return acc;
    },
    {} as Record<InspectionType, { was: boolean | null; now: boolean | null }>,
  );
};

// get the changed inspections of a user between start and end.
export const getChangedInspectionsOfCollections = async (
  options: PaginateRequest & {
    start: Date;
    end: Date;
    collectionIds: number[];
  },
  prisma: PrismaClient,
): Promise<Diffs> => {
  const start = options.start;
  start.setDate(start.getDate() - 1);
  // get the latest 10 scan reports of the user - using the collectionId
  const reports = (await prisma.$queryRaw(
    Prisma.sql`
    WITH last_report AS (
        SELECT DISTINCT ON (sr.uri) * FROM scan_reports sr WHERE "createdAt" >= ${start} AND "createdAt" <= ${
          options.end
        } AND EXISTS(select 1 from target_collections tc 
            WHERE sr.uri = tc.uri AND tc."collectionId" IN (${Prisma.join(
              options.collectionIds,
            )})
        ) ORDER BY sr.uri, "createdAt" DESC
    ),
    not_in_interval AS (
        SELECT DISTINCT ON (nii.uri)
        *
        FROM scan_reports nii
        WHERE nii."createdAt" <= ${start}
     AND exists(SELECT 1 from last_report where last_report.uri = nii.uri)
        ORDER BY nii.uri,nii."createdAt" DESC
    ),
    in_interval AS (
        SELECT DISTINCT ON (scan_reports.uri)
        scan_reports.*
        FROM scan_reports
        WHERE exists(SELECT 1 from last_report where last_report.uri = scan_reports.uri) AND NOT EXISTS(
            SELECT 1 from not_in_interval nii where nii.uri = scan_reports.uri
            )
        ORDER BY scan_reports.uri, scan_reports."createdAt" ASC
    ),
    second_last_report AS (
        SELECT * from not_in_interval
        UNION
        SELECT * from in_interval
    )
    SELECT row_to_json(sr1.*) as "lastReport", row_to_json(sr2.*) as "secondLastReport" from last_report sr1
    INNER JOIN second_last_report sr2 ON sr1.uri = sr2.uri
    AND (
        sr2.hsts is distinct from  sr1.hsts OR
        sr2."responsibleDisclosure" is distinct from  sr1."responsibleDisclosure" OR
        sr2."tlsv1_3" is distinct from sr1."tlsv1_3" OR
        sr2."deprecatedTLSDeactivated" is distinct from  sr1."deprecatedTLSDeactivated" OR
        sr2."dnsSec" is distinct from sr1."dnsSec" OR
        sr2."rpki" is distinct from  sr1."rpki"
    )
    `,
  )) as Array<{
    lastReport: ScanReport;
    secondLastReport: ScanReport;
  }>;

  return {
    start: options.start.getTime(),
    end: options.end.getTime(),
    uriDiffs: reports.map((report) => {
      return {
        uri: report.lastReport.uri,
        diff: diffReport(report.lastReport, report.secondLastReport),
      };
    }),
  };
};

const combineReport = (
  lastReport: ScanReport | undefined,
  newReport: Omit<ScanReport, "createdAt" | "updatedAt" | "id">,
) => {
  if (lastReport === undefined) {
    return newReport;
  }
  Object.values(InspectionTypeEnum).forEach((key) => {
    if (newReport[key] === null || newReport[key] === undefined) {
      newReport[key] = lastReport[key];
    }
  });
  return newReport;
};

const combineResults = (
  lastReport: ScanReport | undefined,
  lastResults: DTO<ISarifResponse> | undefined | null,
  newResult: DTO<ISarifScanSuccessResponse>,
) => {
  if (lastReport === undefined && lastResults === undefined) {
    return newResult;
  }

  const newResultKeyIndexMap = Object.fromEntries(
    newResult.runs[0].results.map((res, index) => [res.ruleId, index]),
  ) as Record<string, number>;

  const lastResultKeyIndexMap = Object.fromEntries(
    lastResults?.runs[0].results.map((res, index) => [res.ruleId, index]) ?? [],
  ) as Record<string, number>;

  Object.values(InspectionTypeEnum).forEach((key) => {
    // get the index of this inspection
    const index = newResultKeyIndexMap[key];

    if (newResult.runs[0].results[index]?.kind === "notApplicable") {
      // prefer the lastResults since it holds more information.
      const lastResultIndex = lastResultKeyIndexMap[key];

      if (
        lastResults &&
        lastResults.runs[0].results[lastResultIndex] &&
        lastResults.runs[0].results[lastResultIndex].kind !== "notApplicable"
      ) {
        newResult.runs[0].results[index] =
          lastResults.runs[0].results[lastResultIndex];
      } else if (lastReport && lastReport[key] !== null) {
        // at least we have the last report.
        newResult.runs[0].results[index] = {
          ruleId: key,
          kind: lastReport[key] ? "pass" : "fail",
          message: {
            text: "",
          },
          properties: {
            errorIds: [],
            recommendationIds: [],
            actualValue: {},
          },
        };
      }
    }
  });
  return newResult;
};

export const scanResult2ScanReport = (
  result: ISarifScanSuccessResponse,
): Omit<ScanReport, "createdAt" | "updatedAt" | "id"> => {
  return {
    uri: result.runs[0].properties.target,
    ipAddress: result.runs[0].properties.ipAddress,
    duration:
      endTimeOfResponse(result).getTime() -
      startTimeOfResponse(result).getTime(),
    sut: result.runs[0].properties.sut,
    ...(Object.fromEntries(
      result.runs[0].results.map((res) => [
        res.ruleId,
        kind2DidPass(res.kind as "notApplicable" | "pass" | "fail"),
      ]),
    ) as {
      [key in InspectionType]: boolean;
    }),
  };
};

const handleReportDidChange = async (
  newReport: Omit<ScanReport, "createdAt" | "updatedAt" | "id">,
  lastScanDetails: ISarifScanSuccessResponse,
  result: ISarifScanSuccessResponse,
  prisma: PrismaClient,
) => {
  // if the report changed, we need to create a new one.
  const target = await prisma.target.upsert({
    where: { uri: newReport.uri },
    create: {
      lastScanDetails: {
        create: {
          details: lastScanDetails as any,
        },
      },
      uri: newReport.uri,
      queued: false,
      errorCount: 0,
      lastScan: startTimeOfResponse(result).getTime(),
      hostname: getHostnameFromUri(getTargetFromResponse(result)),
    },
    update: {
      queued: false,
      lastScan: startTimeOfResponse(result).getTime(),
      errorCount: 0,
      hostname: getHostnameFromUri(getTargetFromResponse(result)),
      lastScanDetails: {
        upsert: {
          create: {
            details: lastScanDetails as any,
          },
          update: {
            details: lastScanDetails as any,
          },
        },
      },
    },
  });

  await prisma.scanReport.create({
    data: newReport,
  });
  return toDTO({
    ...target,
    lastScan: target.lastScan || 0,
    details: lastScanDetails,
  });
};

// only create a new report if the didPass property changed.
const handleNewScanReport = async (
  requestId: string,
  result: ISarifScanSuccessResponse,
  prisma: PrismaClient,
  options: ScanTargetOptions,
): Promise<DTO<DetailedTarget>> => {
  // fetch the last existing report and check if we only need to update that one.
  const [lastReports, lastResults] = await Promise.all([
    prisma.scanReport.findMany({
      where: {
        uri: result.runs[0].properties.target,
      },
      orderBy: {
        createdAt: "desc",
      },
      take: 1,
    }),
    prisma.lastScanDetails.findFirst({
      where: { uri: result.runs[0].properties.target },
    }),
  ]);

  const lastReport = lastReports.length === 1 ? lastReports[0] : undefined;

  const newReport = combineReport(lastReport, scanResult2ScanReport(result));

  const lastScanDetails = combineResults(
    lastReport,
    !Boolean(lastResults)
      ? null
      : transformDeprecatedReportingSchemaToSarif(
          (lastResults as unknown as { details: DetailsJSON | ISarifResponse })
            .details as any,
        ),
    result,
  );

  if (
    lastReport &&
    config.socks5Proxy &&
    (newReport.duration > config.scanReportDurationThresholdUntilValidation ||
      reportDidChange(lastReport, newReport))
  ) {
    if (
      newReport.duration > config.scanReportDurationThresholdUntilValidation
    ) {
      logger.debug(
        {
          target: getTargetFromResponse(result),
          duration: Date.now() - options.startTimeMS,
        },
        `report for ${getTargetFromResponse(result)} exceeds threshold of ${
          config.scanReportDurationThresholdUntilValidation
        } - verifying the report`,
      );
    } else if (reportDidChange(lastReport, newReport)) {
      logger.debug(
        {
          target: getTargetFromResponse(result),
          duration: Date.now() - options.startTimeMS,
        },
        `report did change for ${getTargetFromResponse(
          result,
        )} - verifying that the report changed`,
      );
    }
    // we should verify that the report changed.
    // lets start another scan, which will use a socks5 proxy configuration
    const validationResult = await scanService.scanRPC(
      requestId,
      getTargetFromResponse(result),
      {
        refreshCache: true, // it makes no sense to use the cache here :)
        socks5Proxy: config.socks5Proxy,
        startTimeMS: options.startTimeMS,
      },
    );

    if (
      isScanSuccess(validationResult) &&
      reportDidChange(
        lastReport,
        combineReport(
          lastReport,
          scanResult2ScanReport(validationResult as ISarifScanSuccessResponse),
        ),
      )
    ) {
      // check if the validation response and the initial result are the same
      // if so, we can safely assume that the report did change.
      logger.debug(
        {
          target: getTargetFromResponse(result),
          duration: Date.now() - options.startTimeMS,
        },
        `report did change for ${getTargetFromResponse(
          result,
        )} - verified that the report changed`,
      );
      return handleReportDidChange(
        newReport,
        lastScanDetails,
        validationResult as ISarifScanSuccessResponse,
        prisma,
      );
    }
    // it was a scan error OR we were not able to verify that the report changed. - lets just return the last report.
    logger.info(
      {
        target: getTargetFromResponse(result),
        duration: Date.now() - options.startTimeMS,
      },
      `could not verify that the report changed for ${getTargetFromResponse(
        result,
      )} - returning last report`,
    );
  } else if (!lastReport || reportDidChange(lastReport, newReport)) {
    return handleReportDidChange(newReport, lastScanDetails, result, prisma);
  }

  const target = await prisma.target.update({
    where: { uri: newReport.uri },
    data: {
      queued: false,
      lastScan: startTimeOfResponse(result).getTime(),
      errorCount: 0,
      hostname: getHostnameFromUri(newReport.uri),
      lastScanDetails: {
        update: {
          updatedAt: endTimeOfResponse(result),
        },
      },
    },
  });

  return toDTO({
    ...target,
    details: result,
  }) as DTO<DetailedTarget>;
};

export const reportService = {
  handleNewScanReport,
  getChangedInspectionsOfCollections,
  reportDidChange,
};
