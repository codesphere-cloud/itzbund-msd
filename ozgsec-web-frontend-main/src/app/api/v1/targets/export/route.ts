import { NextRequest, NextResponse } from "next/server";
import { getCurrentUserOrGuestUser } from "../../../../../utils/server";
import { authOptions } from "../../../../../nextAuthOptions";
import { targetService } from "../../../../../services/targetService";
import { TargetType } from "../../../../../types";
import { prisma } from "../../../../../db/connection";
import { displayInspections } from "../../../../../utils/view";
import { titleMapper } from "../../../../../messages";
import { kind2DidPass } from "../../../../../services/sarifTransformer";

const csvHeader = `domain,${displayInspections
  .map((inspection) => titleMapper[inspection])
  .join(",")}`;

export const GET = async (req: NextRequest) => {
  const searchParams = req.nextUrl.searchParams;
  const search = (searchParams.get("search") as string | undefined) ?? "";
  const collectionIdsStr =
    (searchParams.get("collectionIds") as string | string[] | undefined) ?? "";

  const collectionIds = (
    Array.isArray(collectionIdsStr) ? collectionIdsStr : [collectionIdsStr]
  )
    .map((id) => +id)
    .filter((id) => id > 0);

  const currentUser = await getCurrentUserOrGuestUser(authOptions);

  const targets = await targetService.getUserTargetsWithLatestTestResult(
    currentUser,
    {
      ...Object.fromEntries(searchParams.entries()),
      pageSize: 9999,
      page: 0,
      search,
      collectionIds,
      reverseUriBeforeSort: searchParams.get("reverseUriBeforeSort") === "1",
      type:
        (searchParams.get("domainType") as TargetType | undefined) ||
        TargetType.all,
      sortDirection: searchParams.get("sortDirection") as string | undefined,
    },
    prisma,
  );

  // return it as a csv file
  return new NextResponse(
    Buffer.from(
      `${csvHeader}\n${targets.data
        .map((target) =>
          [
            target.uri,
            ...displayInspections.map(
              (inspection) =>
                kind2DidPass(
                  target.details?.runs[0].results.find(
                    (r) => r.ruleId === inspection,
                  )?.kind,
                ) ?? "",
            ),
          ].join(","),
        )
        .join("\n")}`,
      "utf-8",
    ),
    {
      headers: {
        "Content-Type": "text/csv",
        "Content-Disposition": `attachment; filename="domain-export.csv"`,
      },
    },
  );
};
