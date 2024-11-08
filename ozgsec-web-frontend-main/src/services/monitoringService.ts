import { InfluxDB, Point } from "@influxdata/influxdb-client";
import { config } from "../config";
import { getLogger } from "./logger";

const logger = getLogger(__filename);
const buildService = () => {
  try {
    const { url, token, org, bucket } = config.influx;
    const writeApi = new InfluxDB({ url, token }).getWriteApi(org, bucket);
    return {
      trackSecret: (secret: string) => {
        const point = new Point("secret").tag("value", secret);
        writeApi.writePoint(point);
      },
      trackApiCall: (uri: string, secretOrUserId?: string) => {
        const point = new Point("apiCall")
          .tag("secretOrUserId", secretOrUserId ?? "")
          .stringField("uri", uri);
        writeApi.writePoint(point);
      },
    };
  } catch (e) {
    logger.warn("Unable to initialize monitoring service", e);
    return {
      trackSecret: () => {},
      trackApiCall: () => {},
    };
  }
};

export const monitoringService = buildService();
