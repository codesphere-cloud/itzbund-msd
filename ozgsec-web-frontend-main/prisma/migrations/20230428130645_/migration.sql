/*
  Warnings:

  - You are about to drop the column `group` on the `targets` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "targets_group_idx";

-- AlterTable
ALTER TABLE "targets" DROP COLUMN "group";
