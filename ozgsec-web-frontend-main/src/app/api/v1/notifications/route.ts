import { NextRequest } from "next/server";
import BadRequestException from "../../../../errors/BadRequestException";
import { authOptions } from "../../../../nextAuthOptions";
import { notificationServer } from "../../../../notifications/notificationServer";
import { NotificationType } from "../../../../notifications/notifications";
import { getLogger } from "../../../../services/logger";
import { serverSentEventsService } from "../../../../services/serverSentEventsService";
import {
  eventListenerToAsyncGenerator,
  getCurrentUserOrGuestUser,
} from "../../../../utils/server";

const logger = getLogger(__filename);

// to make it horizontal scalable we need to check if another instance might have received a ping from the client.

// there is no way to detect when to stop streaming notifications to the client - the req.signal abort event is never fired
// https://github.com/vercel/next.js/discussions/48682
export const GET = async (req: NextRequest) => {
  const connectionId = req.nextUrl.searchParams.get("connectionId");
  if (!connectionId) {
    throw new BadRequestException();
  }

  const user = await getCurrentUserOrGuestUser(authOptions);

  logger.debug(
    { userId: user.id, connectionId },
    `new connection for user ${user.id}`,
  );

  const onConnectionDisconnect = serverSentEventsService.newConnection(
    user.id,
    connectionId,
  );

  const asyncGenerator = eventListenerToAsyncGenerator<string>((fn) => {
    // keep the connection alive by sending a heartbeat every 10 seconds.
    const heartbeatInterval = setInterval(() => {
      fn({
        done: false,
        val: JSON.stringify({
          type: NotificationType.HEARTBEAT,
          payload: null,
        }),
      });
    }, 30 * 1_000);

    // send the notifications to the client
    const deregisterListener = notificationServer.onNotification(
      user.id,
      (notification) => {
        logger.debug("sending notification to", user.id);
        fn({ done: false, val: JSON.stringify(notification) });
      },
    );
    onConnectionDisconnect(() => {
      deregisterListener();
      clearInterval(heartbeatInterval);
      fn({ done: true, val: "" });
    });
  });

  const encoder = new TextEncoder();

  return new Response(
    new ReadableStream({
      async pull(controller) {
        const { value, done } = await asyncGenerator.next();
        if (done) {
          controller.close();
          return;
        }
        controller.enqueue(
          encoder.encode(serverSentEventsService.transformToSSE(value)),
        );
      },
    }),
    {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "Content-Encoding": "none",
      },
    },
  );
};
