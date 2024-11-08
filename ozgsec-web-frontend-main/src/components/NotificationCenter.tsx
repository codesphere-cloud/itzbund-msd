"use client";

import { faTimes } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useEffect, useState } from "react";
import { notificationClient } from "../notifications/notificationClient";
import { NotificationType, hasPayload } from "../notifications/notifications";
import { classNames } from "../utils/common";

interface NotificationView {
  title: string;
  description: string;
  id: string;
}

const NotificationCenter = () => {
  const [notifications, setNotifications] = useState<NotificationView[]>([]);
  const [cleared, setCleared] = useState<{ [id: string]: boolean }>({});
  useEffect(() => {
    const unsub = notificationClient.on(
      NotificationType.DOMAIN_IMPORT_PROGRESS,
      {
        id: "domain-import-progress",
        fn: (notification) => {
          if (hasPayload(notification)) {
            setNotifications((prev) => {
              // check if we should replace the notification
              const index = prev.findIndex((n) => n.id === notification.id);
              if (index > -1) {
                prev[index].description = `Der Import der Domains ist zu ${(
                  (notification.payload.current / notification.payload.total) *
                  100
                ).toFixed(0)}% abgeschlossen.`;
                return [...prev];
              }

              return [
                ...prev,
                {
                  title: "Domain-Import",
                  description: `Der Import der Domains ist zu ${(
                    (notification.payload.current /
                      notification.payload.total) *
                    100
                  ).toFixed(0)}% abgeschlossen.`,
                  id: notification.id,
                },
              ];
            });
          }
        },
      },
    );
    return () => {
      unsub();
    };
  }, []);
  return (
    <div className="bg-dunkelblau-100 text-sm text-white">
      {notifications.map((notification, i, arr) => {
        if (cleared[notification.id]) {
          return null;
        }
        return (
          <div
            key={notification.id}
            className={classNames(
              "transition-all duration-500 ease-in-out",
              i + 1 !== arr.length ? "border-b border-dunkelblau-80" : "",
            )}
          >
            <div
              className={classNames(
                "max-w-screen-2xl flex flex-row justify-between mx-auto px-8 py-4 items-center",
              )}
            >
              <div>
                <span className="font-bold">{notification.title}:</span>&nbsp;
                {notification.description}
              </div>
              <button
                onClick={() => {
                  setCleared((prev) => {
                    prev[notification.id] = true;
                    return { ...prev };
                  });
                }}
                className="hover:bg-white/20 transition-all rounded-full w-9 h-9 bg-red flex flex-row justify-center items-center"
              >
                <FontAwesomeIcon icon={faTimes} />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default NotificationCenter;
