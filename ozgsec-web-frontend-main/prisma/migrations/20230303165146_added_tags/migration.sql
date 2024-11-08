-- CreateTable
CREATE TABLE "tags" (
    "id" SERIAL NOT NULL,
    "title" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "color" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tags_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_target_tags" (
    "A" INTEGER NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "tags_title_userId_key" ON "tags"("title", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "_target_tags_AB_unique" ON "_target_tags"("A", "B");

-- CreateIndex
CREATE INDEX "_target_tags_B_index" ON "_target_tags"("B");

-- AddForeignKey
ALTER TABLE "tags" ADD CONSTRAINT "tags_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_target_tags" ADD CONSTRAINT "_target_tags_A_fkey" FOREIGN KEY ("A") REFERENCES "tags"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_target_tags" ADD CONSTRAINT "_target_tags_B_fkey" FOREIGN KEY ("B") REFERENCES "targets"("uri") ON DELETE CASCADE ON UPDATE CASCADE;
