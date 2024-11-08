import { GlobalRef } from "../services/globalRef";
import { rabbitMQRPCClient } from "../services/rabbitmqClient";
import { prisma } from "../db/connection";
import { HashedScanService } from "./hashedScanService";
import { ScanService } from "./scanService";
import { featureFlags } from "../feature-flags";

/**
 * The module returns the according scan service that should be used globally in the application.
 * The decision which service should be used depends on the activation or deactivation of the dashboard
 * If the dashboard is disabled, it is unnecessary to have the URIs in the database.
 */

export const scanService = new GlobalRef("scanService", () => {
  if (!featureFlags.dashboardEnabled) {
    return new HashedScanService(rabbitMQRPCClient, prisma);
  } else return new ScanService(rabbitMQRPCClient, prisma);
}).value;
