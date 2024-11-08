import { PrismaClient } from "@prisma/client";
import { getLogger } from "./logger";
import { statService } from "./statService";

const logger = getLogger(__filename);
const createConnection = async (
  targetUri: string[],
  collectionId: number,
  prisma: PrismaClient,
) => {
  const res = await prisma.targetCollectionRelation.createMany({
    data: targetUri.map((uri) => ({
      collectionId,
      uri,
    })),
    skipDuplicates: true,
  });

  // there is no need to avoid this, as it is a background task.
  statService
    .deleteStatsOfCollection(collectionId, prisma)
    .catch((err) => logger.error(err));

  return res;
};

const deleteConnection = async (
  targetUri: string[],
  collectionId: number,
  prisma: PrismaClient,
) => {
  const res = await prisma.targetCollectionRelation.deleteMany({
    where: {
      collectionId,
      uri: {
        in: targetUri,
      },
    },
  });
  // there is no need to avoid this, as it is a background task.
  statService
    .deleteStatsOfCollection(collectionId, prisma)
    .catch((err) => logger.error(err));
  return res;
};

export const targetCollectionService = {
  createConnection,
  deleteConnection,
};
