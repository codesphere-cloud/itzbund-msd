import { getLogger } from "../services/logger";

const logger = getLogger(__filename);

const podName = process.env.POD_NAME;
const leaderElectorUrl = process.env.LEADER_ELECTOR_URL;

const master: { name: string } = {
  name: "",
};

// Make an async request to the sidecar at http://localhost:4040
const updateMaster = async (url: string) => {
  const response = await fetch(url);
  const data = await response.json();
  master.name = data.name;
};

if (podName && leaderElectorUrl) {
  updateMaster(leaderElectorUrl)
    .then(() => {
      logger.debug(`The master is ${master.name}`);
    })
    .catch((e) => {
      logger.error(e, "Leader election failed");
      process.exit(1);
    });
  setInterval(() => updateMaster(leaderElectorUrl), 60_000);
}

export const isMaster = () => {
  if (process.env.POD_NAME == undefined) {
    logger.debug("POD_NAME is not set - always master");
    return true;
  }
  return master.name === process.env.POD_NAME;
};
