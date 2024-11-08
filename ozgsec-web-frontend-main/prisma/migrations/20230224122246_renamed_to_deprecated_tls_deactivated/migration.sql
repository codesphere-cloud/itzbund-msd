/*
  Warnings:

  - You are about to drop the column `tlsv1_1_Deactivated` on the `scan_reports` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "scan_reports" DROP COLUMN "tlsv1_1_Deactivated",
ADD COLUMN     "deprecatedTLSDeactivated" BOOLEAN;
