import { randomUUID } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../../../db/connection";
import ForbiddenException from "../../../../../../errors/ForbiddenException";
import MethodNotAllowed from "../../../../../../errors/MethodNotAllowed";
import NotFoundException from "../../../../../../errors/NotFoundException";
import { authOptions } from "../../../../../../nextAuthOptions";
import { collectionService } from "../../../../../../services/collectionService";
import { getCurrentUser } from "../../../../../../utils/server";
import { Params } from "../params";

export async function POST(_req: NextRequest, { params }: Params) {
  const collectionId = parseInt(params.collectionId as string);
  if (isNaN(collectionId)) {
    throw new MethodNotAllowed();
  }

  // fetch the collection from the database
  const [collection, currentUser] = await Promise.all([
    prisma.collection.findUnique({
      where: {
        id: collectionId,
      },
    }),
    getCurrentUser(authOptions),
  ]);

  if (!collection) {
    throw new NotFoundException();
  }

  if (
    !collectionService.isUserAllowedToModifyCollection(collection, currentUser)
  ) {
    throw new ForbiddenException();
  }
  const link = await prisma.shareLink.create({
    data: {
      // generate a random secret
      secret: randomUUID(),
      collection: {
        connect: {
          id: collectionId,
        },
      },
    },
  });
  return NextResponse.json(link);
}
