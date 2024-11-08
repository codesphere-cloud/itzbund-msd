"use client";

import {
  faCheckCircle,
  faExclamationCircle,
  faInfoCircle,
  faTimesCircle,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import EventEmitter from "events";
import { useEffect, useState } from "react";
import useDelayChange from "../hooks/useDelayChange";
import { classNames } from "../utils/common";

const toastEventEmitter = new EventEmitter();

type Toast = {
  msg: string;
  type: "success" | "error" | "warning" | "info";
  duration?: number;
};
export const toast = (obj: Toast) => {
  toastEventEmitter.emit("toast", obj);
};
let timeout: NodeJS.Timeout;

const bgColor = (type: Toast["type"]) => {
  switch (type) {
    case "success":
      return "bg-lightning-900 border border-lightning-500";
    case "error":
      return "bg-red-900 border border-red-500";
    case "warning":
      return "bg-yellow-900 border border-yellow-500";
    default:
      return "bg-dunkelblau-100 border border-deepblue-50";
  }
};

const iconName = (type: Toast["type"]) => {
  switch (type) {
    case "success":
      return faCheckCircle;
    case "error":
      return faTimesCircle;
    case "warning":
      return faExclamationCircle;
    default:
      return faInfoCircle;
  }
};

const textColor = (type: Toast["type"]) => {
  switch (type) {
    case "success":
    case "warning":
      return "text-deepblue-500";
    case "error":
    default:
      return "text-white";
  }
};

const Toaster = () => {
  const [toast, setToast] = useState<Toast | null>(null);
  const delayedToast = useDelayChange(toast);
  useEffect(() => {
    toastEventEmitter.addListener("toast", (obj) => {
      if (timeout) clearTimeout(timeout);

      setToast(obj);
      timeout = setTimeout(() => {
        setToast(null);
      }, obj.duration || 3000);
    });
    return () => {
      toastEventEmitter.removeAllListeners("toast");
    };
  }, []);
  return (
    <div id="toast-container" className="relative text-sm pointer-events-none">
      <div
        className={classNames(
          "fixed top-16 right-5 flex gap-2 items-center flex-row z-20 px-4 py-2 transition-all",
          "toast",
          Boolean(toast) ? "opacity-100" : "opacity-0",
          bgColor(toast?.type ?? delayedToast?.type ?? "info"),
          textColor(toast?.type ?? delayedToast?.type ?? "info"),
        )}
      >
        <FontAwesomeIcon
          className={textColor(toast?.type ?? delayedToast?.type ?? "info")}
          icon={iconName(toast?.type ?? delayedToast?.type ?? "info")}
        />
        <p>{toast?.msg ?? delayedToast?.msg}</p>
      </div>
    </div>
  );
};

export default Toaster;
