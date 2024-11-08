import { PrismaClient, ShareLink, User } from "@prisma/client";

const getShareLinksOfUser = async (user: User, prisma: PrismaClient) => {
  const shareLinks = await prisma.shareLink.findMany({
    where: {
      collection: {
        ownerId: user.id,
      },
    },
  });
  return shareLinks;
};

export const shareLinkService = {
  getShareLinksOfUser,
};
