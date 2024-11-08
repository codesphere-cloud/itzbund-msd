/*
  Warnings:

  - You are about to drop the `_user_tags` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `tags` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `target_tag_relations` table. If the table is not empty, all the data it contains will be lost.
  - A unique constraint covering the columns `[defaultCollectionId]` on the table `users` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `defaultCollectionId` to the `users` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "_user_tags" DROP CONSTRAINT "_user_tags_A_fkey";

-- DropForeignKey
ALTER TABLE "_user_tags" DROP CONSTRAINT "_user_tags_B_fkey";

-- DropForeignKey
ALTER TABLE "tags" DROP CONSTRAINT "tags_ownerId_fkey";

-- DropForeignKey
ALTER TABLE "target_tag_relations" DROP CONSTRAINT "target_tag_relations_tagId_fkey";

-- DropForeignKey
ALTER TABLE "target_tag_relations" DROP CONSTRAINT "target_tag_relations_uri_fkey";

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "defaultCollectionId" INTEGER NOT NULL;

-- DropTable
DROP TABLE "_user_tags";

-- DropTable
DROP TABLE "tags";

-- DropTable
DROP TABLE "target_tag_relations";

-- CreateTable
CREATE TABLE "target_collection_relations" (
    "uri" TEXT NOT NULL,
    "collectionId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "target_collection_relations_pkey" PRIMARY KEY ("uri","collectionId")
);

-- CreateTable
CREATE TABLE "collections" (
    "id" SERIAL NOT NULL,
    "title" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "color" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "collections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_user_collections" (
    "A" INTEGER NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "_user_collections_AB_unique" ON "_user_collections"("A", "B");

-- CreateIndex
CREATE INDEX "_user_collections_B_index" ON "_user_collections"("B");

-- CreateIndex
CREATE UNIQUE INDEX "users_defaultCollectionId_key" ON "users"("defaultCollectionId");

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_defaultCollectionId_fkey" FOREIGN KEY ("defaultCollectionId") REFERENCES "collections"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "target_collection_relations" ADD CONSTRAINT "target_collection_relations_uri_fkey" FOREIGN KEY ("uri") REFERENCES "targets"("uri") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "target_collection_relations" ADD CONSTRAINT "target_collection_relations_collectionId_fkey" FOREIGN KEY ("collectionId") REFERENCES "collections"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "collections" ADD CONSTRAINT "collections_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_user_collections" ADD CONSTRAINT "_user_collections_A_fkey" FOREIGN KEY ("A") REFERENCES "collections"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_user_collections" ADD CONSTRAINT "_user_collections_B_fkey" FOREIGN KEY ("B") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
