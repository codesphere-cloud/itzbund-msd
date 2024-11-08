import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../../db/connection";

import ForbiddenException from "../../../../../errors/ForbiddenException";
import NotFoundException from "../../../../../errors/NotFoundException";
import { authOptions } from "../../../../../nextAuthOptions";
import { collectionService } from "../../../../../services/collectionService";
import { getCurrentUser } from "../../../../../utils/server";
import { Params } from "./params";

const getCollection = async (collectionId: number) => {
  const collection = await prisma.collection.findUnique({
    where: {
      id: collectionId,
    },
  });

  if (collection === null) {
    throw new NotFoundException();
  }
  return collection;
};

export async function DELETE(_request: NextRequest, { params }: Params) {
  const collectionId = parseInt(params.collectionId as string);
  const [currentUser, collection] = await Promise.all([
    getCurrentUser(authOptions),
    getCollection(collectionId),
  ]);

  if (
    !collectionService.isUserAllowedToModifyCollection(collection, currentUser)
  ) {
    throw new ForbiddenException();
  }
  // the user is allowed to delete the collection.
  await prisma.collection.delete({
    where: {
      id: collectionId,
    },
  });

  return NextResponse.json({ success: true }, { status: 200 });
}

export async function PUT(req: NextRequest, { params }: Params) {
  const collectionId = parseInt(params.collectionId as string);
  const [currentUser, collection, reqBody] = await Promise.all([
    getCurrentUser(authOptions),
    getCollection(collectionId),
    req.json(),
  ]);

  if (
    !collectionService.isUserAllowedToModifyCollection(collection, currentUser)
  ) {
    throw new ForbiddenException();
  }
  // update the collection
  return NextResponse.json(
    await prisma.collection.update({
      where: {
        id: collection.id,
      },
      data: {
        title: reqBody.title,
        color: reqBody.color,
      },
      include: {
        shareLinks: true,
      },
    }),
  );
}
