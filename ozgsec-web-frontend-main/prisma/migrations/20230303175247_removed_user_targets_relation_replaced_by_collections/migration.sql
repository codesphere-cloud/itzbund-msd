/*
  Warnings:

  - You are about to drop the `user_target_relations` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "user_target_relations" DROP CONSTRAINT "user_target_relations_uri_fkey";

-- DropForeignKey
ALTER TABLE "user_target_relations" DROP CONSTRAINT "user_target_relations_userId_fkey";

-- DropTable
DROP TABLE "user_target_relations";
