-- DropForeignKey
ALTER TABLE "tags" DROP CONSTRAINT "tags_userId_fkey";

-- CreateTable
CREATE TABLE "_user_tags" (
    "A" INTEGER NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "_user_tags_AB_unique" ON "_user_tags"("A", "B");

-- CreateIndex
CREATE INDEX "_user_tags_B_index" ON "_user_tags"("B");

-- AddForeignKey
ALTER TABLE "_user_tags" ADD CONSTRAINT "_user_tags_A_fkey" FOREIGN KEY ("A") REFERENCES "tags"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_user_tags" ADD CONSTRAINT "_user_tags_B_fkey" FOREIGN KEY ("B") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
