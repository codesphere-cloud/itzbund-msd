/*
  Warnings:

  - You are about to drop the `user_domain_relations` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "user_domain_relations" DROP CONSTRAINT "user_domain_relations_uri_fkey";

-- DropForeignKey
ALTER TABLE "user_domain_relations" DROP CONSTRAINT "user_domain_relations_userId_fkey";

-- DropTable
DROP TABLE "user_domain_relations";

-- CreateTable
CREATE TABLE "user_target_relations" (
    "userId" TEXT NOT NULL,
    "uri" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_target_relations_pkey" PRIMARY KEY ("userId","uri")
);

-- AddForeignKey
ALTER TABLE "user_target_relations" ADD CONSTRAINT "user_target_relations_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_target_relations" ADD CONSTRAINT "user_target_relations_uri_fkey" FOREIGN KEY ("uri") REFERENCES "targets"("uri") ON DELETE CASCADE ON UPDATE CASCADE;
