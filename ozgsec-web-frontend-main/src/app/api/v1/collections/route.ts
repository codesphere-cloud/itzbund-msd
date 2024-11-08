import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../db/connection";
import { authOptions } from "../../../../nextAuthOptions";
import { getCurrentUserOrGuestUser } from "../../../../utils/server";

export async function POST(req: NextRequest) {
  const currentUser = await getCurrentUserOrGuestUser(authOptions);
  const collection: { title: string; color: string } = await req.json();

  const d = await prisma.collection.create({
    data: {
      title: collection.title,
      color: collection.color,
      owner: {
        connect: {
          id: currentUser.id,
        },
      },
    },
    include: {
      shareLinks: true,
    },
  });

  return NextResponse.json(d);
}
