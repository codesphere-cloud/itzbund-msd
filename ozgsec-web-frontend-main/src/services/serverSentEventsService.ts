import EventEmitter from "node:events";
import { getLogger } from "./logger";
import { GlobalRef } from "./globalRef";
import { rabbitMQClient } from "./rabbitmqClient";
import { HorizontalScalingAdapter } from "./HorizontalScalingAdapter";

const logger = getLogger(__filename);

class ServerSentEventsService {
  private connectedClients: {
    [userId: string]:
      | {
          eventEmitter: EventEmitter;
          disconnectedTimeout: NodeJS.Timeout;
        }
      | undefined;
  } = {};

  constructor(
    private readonly horizontalScalingAdapter?: HorizontalScalingAdapter,
  ) {}

  public bootstrap() {
    if (this.horizontalScalingAdapter) {
      this.horizontalScalingAdapter.subscribe("quicktest:heartbeats", (msg) => {
        const { userId, connectionId } = msg as {
          userId: string;
          connectionId: string;
        };
        this.localEmitHeartbeat(userId, connectionId);
      });
    }
  }

  private localEmitHeartbeat(userId: string, connectionId: string) {
    if (!this.connectedClients[`${userId}:${connectionId}`]) {
      // the user is not connected to this instance - do nothing
      // this happens when the user is connected to another instance - horizontal scaling
      return;
    }

    clearTimeout(
      this.connectedClients[`${userId}:${connectionId}`]!.disconnectedTimeout,
    );
    // set a new timeout
    this.connectedClients[`${userId}:${connectionId}`]!.disconnectedTimeout =
      this.disconnectTimeoutFactory(userId, connectionId);
  }

  public transformToSSE(data: string) {
    return `data: ${data}\n\n`;
  }

  public heartbeat(userId: string, connectionId: string) {
    // if the distribution adapter is provided, we just publish it
    if (this.horizontalScalingAdapter) {
      this.horizontalScalingAdapter.publish("quicktest:heartbeats", {
        userId,
        connectionId,
      });
    } else {
      this.localEmitHeartbeat(userId, connectionId);
    }
  }

  private disconnectTimeoutFactory(userId: string, connectionId: string) {
    return setTimeout(() => {
      logger.debug(
        { userId, connectionId },
        `disconnecting user ${userId} due to inactivity`,
      );

      const mapKey = `${userId}:${connectionId}`;

      this.connectedClients[mapKey]?.eventEmitter?.emit(`disconnect`);
      // remove all listeners to avoid a memory leak
      this.connectedClients[mapKey]?.eventEmitter?.removeAllListeners();
      delete this.connectedClients[mapKey];
    }, 60 * 1_000); // 60 seconds
  }

  public newConnection(userId: string, connectionId: string) {
    const eventEmitter = new EventEmitter();
    this.connectedClients[`${userId}:${connectionId}`] = {
      eventEmitter,
      disconnectedTimeout: this.disconnectTimeoutFactory(userId, connectionId),
    };

    return (fn: () => void) => eventEmitter.on("disconnect", fn);
  }

  public getConnectedClients() {
    return Object.keys(this.connectedClients).length;
  }
}
// pretty much the only reason for the serverSentEventsService object is to keep track of the connected clients and disconnect them if they are inactive for too long.
// it would be much simpler to just detect if the event source request (SSE) is closed and then disconnect the user - but this is not possible with nextjs at the moment: https://github.com/vercel/next.js/discussions/48682
export const serverSentEventsService = new GlobalRef(
  "serverSentEventsService",
  () => new ServerSentEventsService(rabbitMQClient),
).value;
