import { clientHttpClient } from "../services/clientHttpClient";
import { once } from "../utils/common";
import {
  Notification,
  NotificationMap,
  NotificationType,
} from "./notifications";

type NotificationListener<T extends NotificationType> = (
  notification: NotificationMap[T],
) => void;

const notificationListeners: {
  [type in NotificationType]?: Array<{
    id: string;
    fn: (notification: NotificationMap[type]) => void;
  }>;
} = {};

const start = once(() => {
  // use a connectionId - just using the userId to detect, if a connection is still alive is not enough
  // a simple reload will kill the event source connection but the user is still logged in
  const connectionId = crypto.randomUUID();
  const evtSource = new EventSource(
    `/api/v1/notifications?connectionId=${connectionId}`,
  );
  evtSource.addEventListener("message", (e) => {
    // route the message to the correct listener
    const notification = JSON.parse(e.data) as Notification<any>;
    notificationListeners[notification.type]?.forEach((l) => {
      // @ts-expect-error
      l.fn(notification as NotificationMap[typeof notification.type]);
    });
  });
  // setup the heartbeat
  const interval = setInterval(async () => {
    const res = await clientHttpClient(
      `/api/v1/notifications/heartbeat?connectionId=${connectionId}`,
      crypto.randomUUID(),
    );
    if (!res.ok) {
      console.log("heartbeat failed - closing connection");
      evtSource.close();
      clearInterval(interval);
    }
  }, 30_000);
});

const on = <T extends NotificationType>(
  type: T,
  {
    id,
    fn,
  }: {
    id: string;
    fn: NotificationListener<T>;
  },
) => {
  start(); // idempotent - will be noop if already started
  if (!notificationListeners[type]) {
    notificationListeners[type] = [];
  }
  // check if the listener is already registered by id
  if (notificationListeners[type]?.some((l) => l.id === id)) {
    console.log("listener already registered - skipping");
    return () => {};
  }
  notificationListeners[type]?.push({ fn, id });

  return () => {
    // remove the listener
    // @ts-expect-error
    notificationListeners[type] = notificationListeners[type]?.filter(
      (l) => l.id !== id,
    );
  };
};

export const notificationClient = {
  on,
};
