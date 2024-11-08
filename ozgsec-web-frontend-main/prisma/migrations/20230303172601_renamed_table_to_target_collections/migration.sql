/*
  Warnings:

  - You are about to drop the `target_collection_relations` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "target_collection_relations" DROP CONSTRAINT "target_collection_relations_collectionId_fkey";

-- DropForeignKey
ALTER TABLE "target_collection_relations" DROP CONSTRAINT "target_collection_relations_uri_fkey";

-- DropTable
DROP TABLE "target_collection_relations";

-- CreateTable
CREATE TABLE "target_collections" (
    "uri" TEXT NOT NULL,
    "collectionId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "target_collections_pkey" PRIMARY KEY ("uri","collectionId")
);

-- AddForeignKey
ALTER TABLE "target_collections" ADD CONSTRAINT "target_collections_uri_fkey" FOREIGN KEY ("uri") REFERENCES "targets"("uri") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "target_collections" ADD CONSTRAINT "target_collections_collectionId_fkey" FOREIGN KEY ("collectionId") REFERENCES "collections"("id") ON DELETE CASCADE ON UPDATE CASCADE;
