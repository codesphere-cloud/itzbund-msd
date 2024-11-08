/*
  Warnings:

  - A unique constraint covering the columns `[secret]` on the table `share_links` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "share_links_secret_key" ON "share_links"("secret");
