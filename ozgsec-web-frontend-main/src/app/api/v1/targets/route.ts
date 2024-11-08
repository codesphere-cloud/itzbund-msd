import PQueue from "p-queue";

import { targetService } from "../../../../services/targetService";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../db/connection";
import BadRequestException from "../../../../errors/BadRequestException";
import { authOptions } from "../../../../nextAuthOptions";
import { notificationServer } from "../../../../notifications/notificationServer";
import { NotificationType } from "../../../../notifications/notifications";
import { scanService } from "../../../../scanner/scanner.module";
import { getLogger } from "../../../../services/logger";
import {
  isScanError,
  neverThrow,
  sanitizeURI,
  splitLineBreak,
} from "../../../../utils/common";
import { getCurrentUser, toDTO } from "../../../../utils/server";
import { collectionService } from "../../../../services/collectionService";
import { featureFlags } from "../../../../feature-flags";

const logger = getLogger(__filename);

export async function POST(req: NextRequest) {
  const currentUser = await getCurrentUser(authOptions);
  const requestId = req.headers.get("x-request-id") as string;
  // check if the user uploads a file or only inputs a single domain.
  if (req.headers.get("content-type")?.includes("application/json")) {
    // the user does only send a single domain.

    const {
      target,
      collectionIds,
    }: { target: string; collectionIds?: Array<number> } = await req.json();

    const sanitized = sanitizeURI(target);
    if (!sanitized) {
      throw new BadRequestException();
    }

    await targetService.handleNewTarget(
      {
        uri: sanitized,
        queued: true,
        collectionIds: await collectionService.filterCollectionsToAllowed(
          collectionIds ?? [],
          currentUser,
          prisma,
        ),
      },
      prisma,
      currentUser,
    );

    const [result, detailedTarget] = await scanService.scanTargetRPC(
      requestId,
      sanitized,
      {
        refreshCache: featureFlags.refreshEnabled,
        startTimeMS: Date.now(),
      },
    );
    if (isScanError(result)) {
      logger.error(
        { requestId, userId: currentUser.id },
        `target import - error while scanning domain: ${sanitized}`,
      );

      throw new BadRequestException();
    }

    return NextResponse.json(toDTO(detailedTarget), { status: 201 });
  }

  const formData = await req.formData();
  const files = formData.getAll("files") as File[];

  const fileText = await Promise.all(
    files
      // validate for text files.
      .filter(
        (file) =>
          file.type === "text/csv" || file.type === "application/vnd.ms-excel",
      )
      .map(async (file) => {
        // open the file.
        return file.text();
      }),
  );
  const entries = fileText.map((file) => splitLineBreak(file)).flat();

  const promiseQueue = new PQueue({ concurrency: 5, timeout: 5_000 });

  logger.info(
    { requestId, userId: currentUser.id },
    `starting import of ${entries.length} targets.`,
  );

  let imported = 0;
  const notificationId = crypto.randomUUID();

  promiseQueue.addAll(
    entries
      .map((domain) => sanitizeURI(domain))
      .filter(
        (domain): domain is string => domain !== null && domain.length > 0,
      )
      .map((domain, _, arr) => {
        return async () => {
          try {
            imported++;
            notificationServer.notifyUser(currentUser.id, {
              type: NotificationType.DOMAIN_IMPORT_PROGRESS,
              payload: {
                current: imported,
                total: arr.length,
              },
              id: notificationId,
            });

            // might throw, if the relation does already exist
            await neverThrow(
              targetService.handleNewTarget(
                { uri: domain, queued: true },
                prisma,
                currentUser,
              ),
            );

            const tmpRqId = crypto.randomUUID();

            const [result] = await scanService.scanTargetRPC(tmpRqId, domain, {
              refreshCache: false,
              startTimeMS: Date.now(),
            });
            if (isScanError(result)) {
              logger.error(
                { tmpRqId, userId: currentUser.id },
                `target import - error while scanning domain: ${domain}`,
              );
              return;
            }
          } catch (err: any) {
            logger.error(err);
            return;
          }
        };
      }),
  );

  // check when promise queue is empty
  promiseQueue.onIdle().then(() => {
    notificationServer.notifyUser(currentUser.id, {
      type: NotificationType.DOMAIN_IMPORT_PROGRESS,
      payload: "DONE",
      id: notificationId,
    });
  });

  return NextResponse.json({
    success: true,
  });
}
