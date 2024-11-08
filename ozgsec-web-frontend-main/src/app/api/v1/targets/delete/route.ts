import { PrismaClient, User } from "@prisma/client";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../../db/connection";
import { authOptions } from "../../../../../nextAuthOptions";
import { targetCollectionService } from "../../../../../services/targetCollectionService";
import { getCurrentUser } from "../../../../../utils/server";

const deleteTargetRelation = async (
  uris: string[],
  user: User,
  prisma: PrismaClient,
) => {
  if (uris.length === 0) {
    return;
  }
  // delete it from all collection where this user is owner of or its his default collection.
  const relations = await prisma.targetCollectionRelation.findMany({
    where: {
      OR: [
        {
          uri: {
            in: uris,
          },
          collection: {
            ownerId: user.id,
          },
        },
        {
          uri: {
            in: uris,
          },
          collectionId: user.defaultCollectionId,
        },
      ],
    },
  });
  return Promise.all(
    relations.map((r) =>
      targetCollectionService.deleteConnection(uris, r.collectionId, prisma),
    ),
  );
};

export async function POST(req: NextRequest) {
  const [{ targets }, currentUser] = await Promise.all([
    req.json() as Promise<{ targets: string[] }>,
    getCurrentUser(authOptions),
  ]);
  await deleteTargetRelation(targets, currentUser, prisma);
  return NextResponse.json({
    success: true,
  });
}
