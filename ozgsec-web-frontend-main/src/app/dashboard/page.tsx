import React from "react";
import Content from "./content";
import { getCurrentUserOrGuestUser, toDTO } from "../../utils/server";
import { authOptions } from "../../nextAuthOptions";
import { prisma } from "../../db/connection";
import { statService } from "../../services/statService";
import { collectionService } from "../../services/collectionService";
import {
  collectionId,
  normalizeToMap,
  replaceNullWithZero,
} from "../../utils/common";
import { config } from "../../config";

const Dashboard = async () => {
  const currentUser = await getCurrentUserOrGuestUser(authOptions);

  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);

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

    defaultCollectionId: collectionId(currentUser),
    refCollections: config.generateStatsForCollections,
    collections: normalizeToMap(
      toDTO(collections).map((c) => ({ ...c, size: c._count.targets })),
      "id",
    ),
  };

  return <Content {...props} />;
};

export default Dashboard;
