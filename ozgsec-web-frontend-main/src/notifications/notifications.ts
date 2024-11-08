export enum NotificationType {
  DOMAIN_IMPORT_PROGRESS = "DOMAIN_IMPORT_PROGRESS",
  AUTH = "AUTH", // used for flow control
  HEARTBEAT = "HEARTBEAT",
}

type DONE = "DONE";
export interface Notification<T extends Record<string, any>> {
  type: NotificationType;
  payload: T | DONE;
  id: string;
}

export interface HeartbeatNotification extends Notification<{}> {
  type: NotificationType.HEARTBEAT;
}

export interface NotificationAuthMessage
  // the notificationToken is NOT the jwt. There is no way to validate the token using nextjs without calling
  // a REST-Route. To avoid that, we use an temporary token to do the mapping
  extends Notification<{ notificationToken: string }> {
  type: NotificationType.AUTH;
}

export interface NotificationDomainImportProgress
  extends Notification<{
    total: number;
    current: number;
  }> {
  type: NotificationType.DOMAIN_IMPORT_PROGRESS;
}

export interface NotificationMap {
  [NotificationType.AUTH]: NotificationAuthMessage;
  [NotificationType.DOMAIN_IMPORT_PROGRESS]: NotificationDomainImportProgress;
  [NotificationType.HEARTBEAT]: HeartbeatNotification;
}

export const isDoneNotification = <
  Payload extends Record<string, any>,
  T extends Notification<Payload>,
>(
  notification: T,
): notification is T & { payload: DONE } => {
  return notification.payload === "DONE";
};

export const hasPayload = <
  Payload extends Record<string, any>,
  T extends Notification<Payload>,
>(
  notification: T,
): notification is T & { payload: Payload } => {
  return notification.payload !== "DONE";
};
