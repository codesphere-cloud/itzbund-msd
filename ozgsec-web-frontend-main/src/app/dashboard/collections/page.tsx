import { prisma } from "../../../db/connection";
import { authOptions } from "../../../nextAuthOptions";
import { collectionService } from "../../../services/collectionService";
import { shareLinkService } from "../../../services/shareLinkService";
import { collectionId, isGuestUser } from "../../../utils/common";
import { getCurrentUserOrGuestUser, toDTO } from "../../../utils/server";
import Content from "./content";

const CollectionPage = async () => {
  const currentUser = await getCurrentUserOrGuestUser(authOptions);

  const [collections, links] = await Promise.all([
    collectionService.getAllCollectionsOfUser(currentUser, prisma),
    isGuestUser(currentUser)
      ? []
      : shareLinkService.getShareLinksOfUser(currentUser, prisma),
  ]);

  return (
    <Content
      collections={toDTO(
        collections
          .filter((c) => c.id !== collectionId(currentUser))
          .map((c) => ({
            ...c,
            shareLinks: toDTO(links.filter((l) => l.collectionId === c.id)),
          })),
      )}
    />
  );
};

export default CollectionPage;
