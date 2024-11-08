-- CreateTable
CREATE TABLE "scan_reports" (
    "id" SERIAL NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT,
    "duration" INTEGER NOT NULL,
    "uri" TEXT NOT NULL,
    "sut" TEXT,
    "SubResourceIntegrity" BOOLEAN,
    "NoMixedContent" BOOLEAN,
    "ResponsibleDisclosure" BOOLEAN,
    "DNSSec" BOOLEAN,
    "CAA" BOOLEAN,
    "IPv6" BOOLEAN,
    "RPKI" BOOLEAN,
    "HTTP" BOOLEAN,
    "HTTP308" BOOLEAN,
    "HTTPRedirectsToHttps" BOOLEAN,
    "HTTPS" BOOLEAN,
    "HSTS" BOOLEAN,
    "HSTSPreloaded" BOOLEAN,
    "ContentSecurityPolicy" BOOLEAN,
    "XFrameOptions" BOOLEAN,
    "XSSProtection" BOOLEAN,
    "ContentTypeOptions" BOOLEAN,
    "SecureSessionCookies" BOOLEAN,
    "TLSv1_2" BOOLEAN,
    "TLSv1_3" BOOLEAN,
    "TLSv1_1_Deactivated" BOOLEAN,
    "StrongKeyExchange" BOOLEAN,
    "StrongCipherSuites" BOOLEAN,
    "ValidCertificate" BOOLEAN,
    "StrongPrivateKey" BOOLEAN,
    "StrongSignatureAlgorithm" BOOLEAN,
    "MatchesHostname" BOOLEAN,
    "NotRevoked" BOOLEAN,
    "CertificateTransparency" BOOLEAN,
    "ValidCertificateChain" BOOLEAN,

    CONSTRAINT "scan_reports_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "last_scan_details" (
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "details" JSONB NOT NULL,
    "uri" TEXT NOT NULL,

    CONSTRAINT "last_scan_details_pkey" PRIMARY KEY ("uri")
);

-- CreateTable
CREATE TABLE "targets" (
    "uri" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastScan" BIGINT,
    "errorCount" INTEGER NOT NULL DEFAULT 0,
    "queued" BOOLEAN NOT NULL DEFAULT false,
    "group" TEXT NOT NULL,

    CONSTRAINT "targets_pkey" PRIMARY KEY ("uri")
);

-- CreateTable
CREATE TABLE "user_domain_relations" (
    "userId" TEXT NOT NULL,
    "uri" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_domain_relations_pkey" PRIMARY KEY ("userId","uri")
);

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "role" TEXT,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "networks" (
    "cidr" TEXT NOT NULL,
    "prefixLength" INTEGER NOT NULL,
    "networkAddress" TEXT NOT NULL,
    "startAddressNumber" BIGINT NOT NULL,
    "endAddressNumber" BIGINT NOT NULL,
    "comment" TEXT,

    CONSTRAINT "networks_pkey" PRIMARY KEY ("cidr")
);

-- CreateTable
CREATE TABLE "stats" (
    "subject" TEXT NOT NULL,
    "time" BIGINT NOT NULL,
    "value" JSONB NOT NULL,

    CONSTRAINT "stats_pkey" PRIMARY KEY ("subject","time")
);

-- CreateTable
CREATE TABLE "emails" (
    "email" TEXT NOT NULL,

    CONSTRAINT "emails_pkey" PRIMARY KEY ("email")
);

-- CreateIndex
CREATE INDEX "scan_reports_createdAt_idx" ON "scan_reports"("createdAt");

-- CreateIndex
CREATE INDEX "scan_reports_uri_idx" ON "scan_reports"("uri");

-- CreateIndex
CREATE INDEX "targets_group_idx" ON "targets"("group");

-- CreateIndex
CREATE INDEX "targets_lastScan_idx" ON "targets"("lastScan");

-- CreateIndex
CREATE INDEX "targets_hostname_idx" ON "targets"("hostname");

-- AddForeignKey
ALTER TABLE "scan_reports" ADD CONSTRAINT "scan_reports_uri_fkey" FOREIGN KEY ("uri") REFERENCES "targets"("uri") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "last_scan_details" ADD CONSTRAINT "last_scan_details_uri_fkey" FOREIGN KEY ("uri") REFERENCES "targets"("uri") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_domain_relations" ADD CONSTRAINT "user_domain_relations_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_domain_relations" ADD CONSTRAINT "user_domain_relations_uri_fkey" FOREIGN KEY ("uri") REFERENCES "targets"("uri") ON DELETE CASCADE ON UPDATE CASCADE;
