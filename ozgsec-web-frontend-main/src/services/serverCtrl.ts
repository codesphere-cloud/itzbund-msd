import { randomUUID } from "crypto";
import PQueue from "p-queue";
import { prisma } from "../db/connection";

import { isMaster } from "../leaderelection/leaderelection";
import { ISarifResponse } from "../types";
import { once } from "../utils/common";
import { targetService } from "./targetService";

import { notificationServer } from "../notifications/notificationServer";
import { scanService } from "../scanner/scanner.module";
import { getLogger } from "./logger";
import { rabbitMQClient } from "./rabbitmqClient";
import { serverSentEventsService } from "./serverSentEventsService";
import { statService } from "./statService";
import { featureFlags } from "../feature-flags";

const logger = getLogger(__filename);
// make sure to always execute a function only once.

const bootstrap = once(() => {
  // start the response loops.
  if (featureFlags.dashboardEnabled) {
    startLookupResponseLoop();
    startScanResponseLoop();
    statLoop();
    startScanLoop();
  }
  serverSentEventsService.bootstrap();
  // start the notification server
  notificationServer.bootstrap();
});

const startLookupResponseLoop = () => {
  logger.info("connected to database - starting lookup response loop");
  rabbitMQClient.listen(
    "ip-lookup-response",
    async (msg) => {
      const content = JSON.parse(msg.content.toString()).data as {
        fqdn: string;
      };
      try {
        await targetService.handleNewTarget({ uri: content.fqdn }, prisma);
      } catch (e: any) {
        // always ack the message - catch the error.
        logger.error({ err: e.message });
      }
    },
    { durable: true, maxPriority: 10 },
  );
};

const startScanResponseLoop = () => {
  logger.info("starting scan response loop");
  rabbitMQClient.listen("scan-response", async (msg) => {
    const content = JSON.parse(msg.content.toString()).data as ISarifResponse;
    await scanService.handleScanResponse(crypto.randomUUID(), content, {
      refreshCache: false,
      startTimeMS: Date.now(),
    });
  });
};

const statLoop = () => {
  let running = false;
  const promiseQueue = new PQueue({
    concurrency: 2,
  });
  logger.info("starting stat loop");
  setInterval(async () => {
    if (isMaster() && !running) {
      running = true;

      const collections = await prisma.collection.findMany();

      collections.forEach((collection) => {
        statService.generateStatsForCollection(
          collection.id,
          promiseQueue,
          prisma,
        );
      });

      await promiseQueue.onIdle();

      running = false;
    } else {
      if (!isMaster() && running) {
        logger.warn(
          "not master and already running - this instance is not running stat loop",
        );
      } else if (!isMaster() && !running) {
        logger.warn(
          "not master and not running - this instance is not running stat loop",
        );
      } else if (isMaster() && running) {
        logger.warn("master and not running - stat loop is already running");
      } else {
        logger.warn("stat loop is already running");
      }
    }
  }, 10 * 1000);
};

const startScanLoop = () => {
  let running = false;

  const promiseQueue = new PQueue({
    concurrency: 5,
    timeout: 5 * 1000,
  });

  setInterval(async () => {
    try {
      if (running) {
        logger.warn({ component: "SCAN_LOOP" }, "scan loop is already running");
        return;
      }
      if (!isMaster()) {
        logger.warn({ component: "SCAN_LOOP" }, "scan loop - not master");
        return;
      }
      running = true;
      const targets = await targetService.getTargets2Scan(prisma);

      if (targets.length === 0) {
        running = false;
        logger.info({ component: "SCAN_LOOP" }, "no targets to scan");
        return;
      }
      const requestId = randomUUID();
      logger.info(
        { requestId, component: "SCAN_LOOP" },
        `found ${targets.length} targets to scan - sending scan request with id: ${requestId}`,
      );
      promiseQueue.addAll(
        targets.map((domain) => {
          return async () => {
            return scanService.scanTarget(requestId, domain.uri, {
              refreshCache: false,
              startTimeMS: Date.now(),
            });
          };
        }),
      );

      running = false;
    } catch (e) {
      running = false;
      logger.error(e);
    }
    // does a lookup each minute
  }, 60 * 1000);
};

export const serverCtrl = {
  bootstrap,
};
