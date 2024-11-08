-- CreateTable
CREATE TABLE "share_links" (
    "collectionId" INTEGER NOT NULL,
    "secret" TEXT NOT NULL,

    CONSTRAINT "share_links_pkey" PRIMARY KEY ("collectionId")
);

-- AddForeignKey
ALTER TABLE "share_links" ADD CONSTRAINT "share_links_collectionId_fkey" FOREIGN KEY ("collectionId") REFERENCES "collections"("id") ON DELETE CASCADE ON UPDATE CASCADE;
