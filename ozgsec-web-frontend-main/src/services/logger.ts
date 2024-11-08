import pino from "pino";
import { config } from "../config";

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
});
export const getLogger = (file: string) => {
  if (config.isProduction) {
    return logger;
  }
  return logger;
};
