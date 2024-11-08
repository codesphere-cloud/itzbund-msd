/*
  Warnings:

  - The primary key for the `stats` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `subject` on the `stats` table. All the data in the column will be lost.
  - Added the required column `collectionId` to the `stats` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "stats" DROP CONSTRAINT "stats_pkey",
DROP COLUMN "subject",
ADD COLUMN     "collectionId" INTEGER NOT NULL,
ADD CONSTRAINT "stats_pkey" PRIMARY KEY ("collectionId", "time");

-- AddForeignKey
ALTER TABLE "stats" ADD CONSTRAINT "stats_collectionId_fkey" FOREIGN KEY ("collectionId") REFERENCES "collections"("id") ON DELETE CASCADE ON UPDATE CASCADE;
