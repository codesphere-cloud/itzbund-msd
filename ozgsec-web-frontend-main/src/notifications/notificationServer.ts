import EventEmitter from "events";
import { Notification } from "../notifications/notifications";
import { HorizontalScalingAdapter } from "../services/HorizontalScalingAdapter";
import { GlobalRef } from "../services/globalRef";
import { rabbitMQClient } from "../services/rabbitmqClient";
class NotificationServer {
  private readonly notifications = new EventEmitter();
  constructor(
    private readonly horizontalScalingAdapter?: HorizontalScalingAdapter,
  ) {}

  public bootstrap() {
    this.horizontalScalingAdapter?.subscribe(
      "quicktest:notifications",
      (msg) => {
        const notification = msg as {
          userId: string;
          notification: Notification<any>;
        };
        this.localEmitNotification(
          notification.userId,
          notification.notification,
        );
      },
    );
  }

  private localEmitNotification(
    userId: string,
    notification: Notification<any>,
  ) {
    this.notifications.emit(userId, notification);
  }

  // userId will be used for routing the event to the correct client -
  // if the client is not connected nothing will happen
  notifyUser(userId: string, notification: Notification<any>) {
    if (this.horizontalScalingAdapter) {
      this.horizontalScalingAdapter.publish("quicktest:notifications", {
        userId,
        notification,
      });
    } else {
      this.localEmitNotification(userId, notification);
    }
  }

  onNotification = (
    userId: string,
    callback: (notification: Notification<any>) => void,
  ) => {
    this.notifications.on(userId, callback);
    return () => {
      this.notifications.removeListener(userId, callback);
    };
  };
}
export const notificationServer = new GlobalRef(
  "notificationServer",
  () => new NotificationServer(rabbitMQClient),
).value;
