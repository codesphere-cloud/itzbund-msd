/*
  Warnings:

  - The primary key for the `share_links` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- AlterTable
ALTER TABLE "share_links" DROP CONSTRAINT "share_links_pkey",
ADD CONSTRAINT "share_links_pkey" PRIMARY KEY ("collectionId", "secret");
