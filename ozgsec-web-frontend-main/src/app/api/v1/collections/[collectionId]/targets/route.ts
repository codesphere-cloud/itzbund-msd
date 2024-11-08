import { Target } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../../../db/connection";
import ForbiddenException from "../../../../../../errors/ForbiddenException";
import NotFoundException from "../../../../../../errors/NotFoundException";
import { authOptions } from "../../../../../../nextAuthOptions";
import { collectionService } from "../../../../../../services/collectionService";
import { targetCollectionService } from "../../../../../../services/targetCollectionService";
import { getCurrentUser } from "../../../../../../utils/server";
import { Params } from "../params";

export async function POST(req: NextRequest, { params }: Params) {
  const [currentUser, collection, targets] = await Promise.all([
    getCurrentUser(authOptions),
    prisma.collection.findFirst({
      where: {
        id: parseInt(params.collectionId as string),
      },
    }),
    req.json() as Promise<Target[]>,
  ]);

  if (!collection) {
    throw new NotFoundException();
  }

  if (
    !collectionService.isUserAllowedToModifyCollection(collection, currentUser)
  ) {
    throw new ForbiddenException();
  }

  // add the targets to the collection AND the default collection.
  await targetCollectionService.createConnection(
    targets.map((t) => t.uri),
    collection.id,
    prisma,
  );

  return NextResponse.json({ success: true }, { status: 200 });
}
