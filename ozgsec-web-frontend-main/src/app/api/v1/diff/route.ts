import { groupBy } from "lodash";
import { NextRequest, NextResponse } from "next/server";
import { config } from "../../../../config";
import { prisma } from "../../../../db/connection";
import ForbiddenException from "../../../../errors/ForbiddenException";
import { InspectionType } from "../../../../scanner/scans";
import { authOptions } from "../../../../nextAuthOptions";
import { collectionService } from "../../../../services/collectionService";
import { reportService } from "../../../../services/reportService";
import { Guest } from "../../../../types";
import { isAdmin } from "../../../../utils/common";
import {
  getCurrentUserOrGuestUser,
  getServerSession,
} from "../../../../utils/server";

export async function GET(req: NextRequest) {
  const inspection = req.nextUrl.searchParams.get(
    "inspectionType",
  ) as InspectionType;

  const start = parseInt(req.nextUrl.searchParams.get("start") as string);
  const end = parseInt(req.nextUrl.searchParams.get("end") as string);
  const collectionIds = (
    req.nextUrl.searchParams.get("collectionIds") as string
  )
    .split(",")
    .map((d) => +d)
    .filter((id) => !config.generateStatsForCollections.includes(id));

  let [currentUser, session] = await Promise.all([
    getCurrentUserOrGuestUser(authOptions),
    getServerSession(authOptions),
  ]);

  const forceCollection = req.nextUrl.searchParams.get("forceCollection") as
    | string
    | undefined;
  if (isAdmin(session) && forceCollection) {
    currentUser = {
      id: "admin",
      collectionId: +forceCollection,
      defaultCollectionId: +forceCollection,
    } as Guest;
  }

  // check if the user has access to the collections
  const cols = (
    await collectionService.getAllCollectionsOfUser(currentUser, prisma)
  ).map((c) => c.id);

  const hasAccess = collectionIds.every((c) => cols.includes(c));
  if (!hasAccess) {
    throw new ForbiddenException();
  }

  const inspections = await reportService.getChangedInspectionsOfCollections(
    {
      start: new Date(start),
      end: new Date(end),
      page: 0,
      pageSize: 20,
      collectionIds,
    },
    prisma,
  );

  // filter the inspections by the inspection type
  const filteredInspections = groupBy(
    inspections.uriDiffs
      .filter((d) => {
        return inspection in d.diff;
      })
      .map((d) => ({
        uri: d.uri,
        ...d.diff[inspection],
      })),
    "now",
  );

  return NextResponse.json(filteredInspections);
}
