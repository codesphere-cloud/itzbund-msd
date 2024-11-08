import { Collection, PrismaClient, User } from "@prisma/client";
import { config } from "../config";
import { Guest } from "../types";
import { isGuestUser } from "../utils/common";

const isUserAllowedToModifyCollection = async (
  collection: Collection,
  user: User,
) => {
  // check if the user is the owner of the collection
  return collection.ownerId !== user.id;
};

const getAllCollectionsOfUser = async (
  user: User | Guest,
  prisma: PrismaClient,
  includeRefCollections = false,
) => {
  const queries = isGuestUser(user)
    ? [
        {
          id: user.collectionId,
        },
      ]
    : ([
        {
          ownerId: user.id,
        },
        {
          user: {
            some: {
              id: user.id,
            },
          },
        },
        {
          id: user.defaultCollectionId,
        },
      ] as any[]);
  if (includeRefCollections && config.generateStatsForCollections.length > 0) {
    queries.push({
      id: {
        in: config.generateStatsForCollections,
      },
    });
  }
  const collections = await prisma.collection.findMany({
    where: {
      OR: queries,
    },
    include: {
      _count: {
        select: {
          targets: true,
        },
      },
    },
  });
  return collections;
};

const filterCollectionsToAllowed = async (
  collectionIds: number[],
  user: User,
  prisma: PrismaClient,
) => {
  const cols = (await getAllCollectionsOfUser(user, prisma)).map((c) => c.id);
  const allowed = collectionIds.filter((c) => cols.includes(c));
  return allowed;
};

const getCollectionsOfTargets = async (
  targetUris: string[],
  user: User,
  prisma: PrismaClient,
) => {
  // does not return the users default collection
  const collections = await prisma.targetCollectionRelation.findMany({
    where: {
      OR: [
        {
          uri: {
            in: targetUris,
          },
          collection: {
            user: {
              some: {
                id: user.id, // or if it is shared with the user
              },
            },
          },
        },
        {
          uri: {
            in: targetUris,
          },
          collection: {
            ownerId: user.id, // or if he is the creator of the collection
          },
        },
      ],
    },
  });
  return collections;
};

export const collectionService = {
  getAllCollectionsOfUser,
  getCollectionsOfTargets,
  isUserAllowedToModifyCollection,
  filterCollectionsToAllowed,
  countTargetsInCollections: async (
    prisma: PrismaClient,
  ): Promise<Record<number, number>> => {
    return (
      await prisma.targetCollectionRelation.groupBy({
        by: ["collectionId"],
        _count: true,
      })
    ).reduce(
      (acc, cur) => {
        acc[cur.collectionId] = cur._count;
        return acc;
      },
      {} as Record<number, number>,
    );
  },
};
