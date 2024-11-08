import { revalidatePath } from "next/cache";
import { config } from "../../../config";
import { prisma } from "../../../db/connection";
import { authOptions } from "../../../nextAuthOptions";
import { collectionService } from "../../../services/collectionService";
import { statService } from "../../../services/statService";
import { Guest } from "../../../types";
import {
  collectionId,
  isAdmin,
  normalizeToMap,
  replaceNullWithZero,
} from "../../../utils/common";
import {
  getCurrentUserOrGuestUser,
  getServerSession,
  toDTO,
} from "../../../utils/server";
import Content from "./content";

const Page = async ({ searchParams }: any) => {
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 2);
  yesterday.setHours(0, 0, 0, 0);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const session = await getServerSession(authOptions);
  let currentUser = await getCurrentUserOrGuestUser(authOptions);

  const forceCollection = searchParams["forceCollection"] as string | undefined;
  if (forceCollection && isAdmin(session)) {
    currentUser = {
      id: "admin",
      defaultCollectionId: +forceCollection,
      collectionId: +forceCollection,
    } as Guest;
  }

  const [dashboard, referenceChartData, collections] = await Promise.all([
    statService.getDashboardForUser(currentUser, prisma),
    statService.getReferenceChartData(prisma),
    collectionService.getAllCollectionsOfUser(currentUser, prisma, true),
  ]);

  const props = {
    dashboard: replaceNullWithZero({
      ...dashboard,
      historicalData: {
        ...dashboard.historicalData,
        ...referenceChartData,
      },
    }),
    username: session?.user.name,
    defaultCollectionId: collectionId(currentUser),
    refCollections: config.generateStatsForCollections,
    collections: normalizeToMap(
      toDTO(collections).map((c) => ({ ...c, size: c._count.targets })),
      "id",
    ),
  };

  return <Content {...props} />;
};

export default Page;
