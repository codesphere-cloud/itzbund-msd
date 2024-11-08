import { prisma } from "../../../db/connection";
import { authOptions } from "../../../nextAuthOptions";
import { collectionService } from "../../../services/collectionService";
import { targetService } from "../../../services/targetService";
import { TargetType } from "../../../types";
import {
  collectionId,
  isGuestUser,
  normalizeToMap,
} from "../../../utils/common";
import { getCurrentUserOrGuestUser, toDTO } from "../../../utils/server";
import Content from "./content";
const Page = async ({ searchParams }: any) => {
  // get the query params.
  const page = +(searchParams["page"] ?? 0);
  const search = searchParams["search"] as string | undefined;
  const collectionIdsStr =
    (searchParams["collectionIds"] as string | string[] | undefined) ?? "";

  const collectionIds = (
    Array.isArray(collectionIdsStr) ? collectionIdsStr : [collectionIdsStr]
  )
    .map((id) => +id)
    .filter((id) => id > 0);

  const currentUser = await getCurrentUserOrGuestUser(authOptions);

  const [targets, collections] = await Promise.all([
    targetService.getUserTargetsWithLatestTestResult(
      currentUser,
      {
        ...searchParams,
        pageSize: 50,
        page,
        search,
        collectionIds,
        reverseUriBeforeSort: searchParams["reverseUriBeforeSort"] === "1",
        type:
          (searchParams["domainType"] as TargetType | undefined) ||
          TargetType.all,
        sortDirection: searchParams["sortDirection"] as string | undefined,
      },
      prisma,
    ),
    collectionService.getAllCollectionsOfUser(currentUser, prisma),
  ]);

  const targetCollections = isGuestUser(currentUser)
    ? []
    : await collectionService.getCollectionsOfTargets(
        targets.data.map((t) => t.uri),
        currentUser,
        prisma,
      );

  const props = {
    targets: {
      ...targets,
      data: targets.data.map((t) => ({
        ...t,
        collections: targetCollections
          .filter((c) => c.uri === t.uri)
          .map((c) => c.collectionId),
      })),
    },
    collections: normalizeToMap(
      toDTO(collections.filter((c) => c.id !== collectionId(currentUser))),
      "id",
    ),
  };

  return <Content {...props} />;
};

export default Page;
