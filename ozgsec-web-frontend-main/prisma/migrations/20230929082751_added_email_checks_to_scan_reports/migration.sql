-- AlterTable
ALTER TABLE "scan_reports" ADD COLUMN     "dane" BOOLEAN,
ADD COLUMN     "dkim" BOOLEAN,
ADD COLUMN     "dmarc" BOOLEAN,
ADD COLUMN     "spf" BOOLEAN,
ADD COLUMN     "starttls" BOOLEAN;
