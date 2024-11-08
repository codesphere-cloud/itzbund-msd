import { randomUUID } from "crypto";

import { NextRequest, NextResponse } from "next/server";
import { authOptions } from "../../../../nextAuthOptions";
import { getLogger } from "../../../../services/logger";

import { scanService } from "../../../../scanner/scanner.module";
import { InspectionType } from "../../../../scanner/scans";
import { monitoringService } from "../../../../services/monitoringService";
import { DetailedTarget, ISarifResponse } from "../../../../types";
import { isScanError } from "../../../../utils/common";
import { DTO, getServerSession } from "../../../../utils/server";
import { displayInspections } from "../../../../utils/view";
import { getTargetFromResponse } from "../../../../services/sarifTransformer";
import { featureFlags } from "../../../../feature-flags";

const logger = getLogger(__filename);

const limitToDisplayedInspections = <
  T extends { details: ISarifResponse | null },
>(
  obj: T,
): T => {
  if (!obj.details) {
    return obj;
  }

  const { details, ...rest } = obj;
  details.runs[0].results = details.runs[0].results.filter((r) =>
    displayInspections.includes(r.ruleId as InspectionType),
  );

  // remove the rules as well we would like to hide
  details.runs[0].tool.driver.rules = details.runs[0].tool.driver.rules.filter(
    (r) => displayInspections.includes(r.id as InspectionType),
  );

  return {
    ...rest,
    details,
  } as T;
};

// exporting for testing purposes
export async function GET(req: NextRequest) {
  const secret = req.nextUrl.searchParams.get("s");
  const session = await getServerSession(authOptions);
  const site = req.nextUrl.searchParams.get("site");
  const refresh = req.nextUrl.searchParams.get("refresh");

  /*if (!session && (!secret || !staticSecrets[secret])) {
    logger.error(`invalid secret provided: ${secret}`);
    return NextResponse.json(
      {
        error: "Invalid secret provided",
        uri: site as string,
      },
      { status: 401 }
    );
  }*/

  // check if the client does provide a request id.
  // if so, use this - otherwise generate a new one.
  const requestId =
    (req.headers.get("x-request-id") as string | undefined) ?? randomUUID();

  try {
    const [result, detailedTarget] = await scanService.scanTargetRPC(
      requestId,
      site,
      {
        refreshCache: featureFlags.refreshEnabled && refresh === "true",
        socks5Proxy: req.nextUrl.searchParams.get("socks5Proxy") ?? undefined,
        startTimeMS: Date.now(),
      },
    );

    monitoringService.trackApiCall(
      getTargetFromResponse(result),
      (secret as string) || session?.user?.id,
    );
    if (isScanError(result)) {
      return NextResponse.json(
        {
          error: result.runs[0].invocations[0].exitCode,
          errorMessage: result.runs[0].invocations[0].exitCodeDescription,
          uri: getTargetFromResponse(result),
        },
        { status: 422 },
      );
    } else {
      return NextResponse.json(
        limitToDisplayedInspections(detailedTarget as DTO<DetailedTarget>)
          .details,
      );
    }
  } catch (e: any) {
    logger.error({ requestId, err: e.message }, `could not scan site: ${site}`);
    return NextResponse.json(
      {
        error: `Missing site to scan or not a valid fully qualified domain name. Please provide the site you would like to scan using the site query parameter. Provided value: ?site=${site}`,
        uri: site as string,
      },
      { status: 400 },
    );
  }
}
