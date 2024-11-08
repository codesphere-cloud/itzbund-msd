/*
  Warnings:

  - You are about to drop the column `userId` on the `tags` table. All the data in the column will be lost.
  - You are about to drop the `_target_tags` table. If the table is not empty, all the data it contains will be lost.
  - Added the required column `ownerId` to the `tags` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "_target_tags" DROP CONSTRAINT "_target_tags_A_fkey";

-- DropForeignKey
ALTER TABLE "_target_tags" DROP CONSTRAINT "_target_tags_B_fkey";

-- DropIndex
DROP INDEX "tags_title_userId_key";

-- AlterTable
ALTER TABLE "tags" DROP COLUMN "userId",
ADD COLUMN     "ownerId" TEXT NOT NULL;

-- DropTable
DROP TABLE "_target_tags";

-- CreateTable
CREATE TABLE "target_tag_relations" (
    "uri" TEXT NOT NULL,
    "tagId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "target_tag_relations_pkey" PRIMARY KEY ("uri","tagId")
);

-- AddForeignKey
ALTER TABLE "target_tag_relations" ADD CONSTRAINT "target_tag_relations_uri_fkey" FOREIGN KEY ("uri") REFERENCES "targets"("uri") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "target_tag_relations" ADD CONSTRAINT "target_tag_relations_tagId_fkey" FOREIGN KEY ("tagId") REFERENCES "tags"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tags" ADD CONSTRAINT "tags_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
