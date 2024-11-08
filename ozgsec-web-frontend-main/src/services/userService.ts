import { PrismaClient, User } from "@prisma/client";
import { FeatureFlag } from "../types";

const findUserById = async (
  id: string,
  prisma: PrismaClient,
): Promise<User> => {
  return prisma.user.findFirstOrThrow({
    where: {
      id,
    },
  });
};

const createUser = async (
  user: { _id: string; featureFlags: Record<FeatureFlag, boolean> },
  prisma: PrismaClient,
): Promise<User> => {
  // then create the user with the network ids.
  const createdUser = await prisma.user.create({
    data: {
      id: user._id,
      featureFlags: user.featureFlags,
      defaultCollection: {
        create: {
          title: "Default",
          color: "#000000",
        },
      },
    },
  });
  return createdUser;
};

const updateUser = async (
  id: string,
  data: { featureFlags: Record<FeatureFlag, boolean> },
  prisma: PrismaClient,
): Promise<User> => {
  // then create the user with the network ids.
  const updatedUser = await prisma.user.update({
    where: {
      id: id,
    },
    data: {
      featureFlags: data.featureFlags,
    },
  });

  return updatedUser;
};

const getAll = async (prisma: PrismaClient): Promise<User[]> => {
  return await prisma.user.findMany();
};

export const userService = {
  findUserById,
  createUser,
  updateUser,
  getAll,
};
