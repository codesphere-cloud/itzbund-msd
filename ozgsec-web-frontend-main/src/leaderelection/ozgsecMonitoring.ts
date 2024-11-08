// read the file and parse it
import { getLogger } from "../services/logger";

interface MonitoringItem {
  uri: string;
  interval: number;
}

// avoid back pressure by storing running monitoring requests inside this object.
const running: { [uri: string]: boolean } = {};

const logger = getLogger(__filename);

const monitoringFn = async (uri: string) => {
  /*// only if this pod is the master
  if (!isMaster() || running[uri]) {
    return;
  }
  running[uri] = true;
  const now = Date.now();
  const [{ icon, results }, connection] = await Promise.all([
    inspect("cron", uri),
    getConnection(),
  ]);

  const report = new connection.models.Report({
    uri,
    duration: Date.now() - now,
    iconHref: icon,
    result: results,
    version: 1,
  });
  await report.save();
  logger.info({ duration: Date.now() - now }, `scanned site: ${uri}`);
  running[uri] = false;
};

export const startMonitoring = async () => {
  const file = await readFile("ozgsec.json", "utf8");
  const data: MonitoringItem[] = JSON.parse(file);
  logger.info(`Monitoring ${data.length} items`);

  data.forEach(({ uri, interval }) => {
    // start monitoring
    setInterval(
      async () => {
        try {
          await monitoringFn(uri);
        } catch (e) {
          logger.error(e, "error while monitoring");
        }
      },
      interval
        ? interval * 1000
        : // defaults to 4 hours.
          1000 * 60 * 60 * 4
    );
  });*/
};
