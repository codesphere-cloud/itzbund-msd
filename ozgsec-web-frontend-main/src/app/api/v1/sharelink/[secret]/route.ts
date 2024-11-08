import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../../db/connection";
import ForbiddenException from "../../../../../errors/ForbiddenException";
import NotFoundException from "../../../../../errors/NotFoundException";
import { authOptions } from "../../../../../nextAuthOptions";
import { collectionService } from "../../../../../services/collectionService";
import { getCurrentUser } from "../../../../../utils/server";

export async function DELETE(
  _: NextRequest,
  { params }: { params: { secret: string } },
) {
  // fetch the sharelink
  const [shareLink, currentUser] = await Promise.all([
    prisma.shareLink.findFirst({
      where: {
        secret: params.secret,
      },
      include: {
        collection: true,
      },
    }),
    getCurrentUser(authOptions),
  ]);
  if (!shareLink) {
    throw new NotFoundException();
  }

  if (
    !collectionService.isUserAllowedToModifyCollection(
      shareLink.collection,
      currentUser,
    )
  ) {
    throw new ForbiddenException();
  }

  await prisma.shareLink.delete({
    where: {
      secret: shareLink.secret,
    },
  });
  return NextResponse.json({ success: true }, { status: 200 });
}
