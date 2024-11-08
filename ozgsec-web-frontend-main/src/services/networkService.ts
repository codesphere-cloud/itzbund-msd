import { Network, PrismaClient } from "@prisma/client";
import { parseNetwork } from "../utils/common";
import { DTO, toDTO } from "../utils/server";

const getAll = async (prisma: PrismaClient) => {
  return toDTO(await prisma.network.findMany());
};

const createNetworks = async (
  networks: string[],
  prisma: PrismaClient,
): Promise<DTO<Network[]>> => {
  // first create all the networks.
  // check which networks do already exist based on the cidr
  const existingNetworks = await prisma.network.findMany({
    where: {
      cidr: {
        in: networks,
      },
    },
  });
  // filter the existing networks.
  const newNetworks = networks.filter(
    (network) =>
      !existingNetworks.find(
        (existingNetwork) => existingNetwork.cidr === network,
      ),
  );
  const data = newNetworks.map(parseNetwork);
  // create the new networks.
  await prisma.network.createMany({
    data,
  });
  return toDTO(data);
};

export const networkService = {
  getAll,
  createNetworks,
};
