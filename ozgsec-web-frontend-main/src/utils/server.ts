import { Prisma, User } from "@prisma/client";
import {
  AuthOptions,
  getServerSession as nextAuthGetServerSession,
} from "next-auth";
import { GetTokenParams, getToken } from "next-auth/jwt";
import { Stream } from "stream";
import { prisma } from "../db/connection";
import { UnauthorizedException } from "../errors/UnauthorizedException";
import { Guest, ISession, IToken } from "../types";
import { isAdmin, isGuestUser } from "./common";
import { userService } from "../services/userService";

export const getServerSession = async (
  options: AuthOptions,
): Promise<ISession | null> => {
  return nextAuthGetServerSession(options) as any as Promise<ISession | null>;
};

export const getJWTToken = async (params: GetTokenParams) => {
  return (await getToken(params)) as unknown as IToken | null;
};

export async function* eventListenerToAsyncGenerator<Data>(
  listenForEvents: (fn: (ev: { val: Data; done: boolean }) => void) => void,
): AsyncGenerator<Data> {
  const eventResolvers: Array<(ev: { val: Data; done: boolean }) => void> = [];
  const eventPromises = [
    new Promise<{ val: Data; done: boolean }>((resolve) => {
      eventResolvers.push(resolve);
    }),
  ];

  listenForEvents((event) => {
    eventPromises.push(
      new Promise((resolve) => {
        eventResolvers.push(resolve);
        eventResolvers.shift()!(event);
      }),
    );
  });

  while (true) {
    const el = await eventPromises.shift()!;
    if (el.done) {
      return;
    }
    yield el.val;
  }
}

export const getSessionAndUser = async (
  options: AuthOptions,
): Promise<{ session: ISession; user: User }> => {
  const session = await getServerSession(options);
  if (!session) {
    throw new UnauthorizedException("no session");
  }
  // check if guest
  if (isGuestUser(session.user)) {
    return {
      session,
      user: {
        id: session.user.id,
        featureFlags: {},
        defaultCollectionId: session.user.collectionId,
      },
    };
  }

  const currentUser = await prisma.user.findFirst({
    where: {
      id: session.user.id,
    },
  });

  if (!currentUser) {
    throw new UnauthorizedException(
      `currentUser with id: ${session.user.id} not found`,
    );
  }

  return { session, user: currentUser };
};

export const getCurrentUserOrGuestUser = async (
  options: AuthOptions,
): Promise<User | Guest> => {
  const session = await getServerSession(options);

  if (!session) {
    throw new UnauthorizedException("no session");
  }

  // check if guest
  if (isGuestUser(session.user)) {
    return session.user;
  }

  const currentUser = await prisma.user.findFirst({
    where: {
      id: session.user.id,
    },
  });

  if (!currentUser) {
    // bootstrap the user
    const user = userService.createUser(
      {
        _id: session.user.id,
        featureFlags: {
          collections: true,
        },
      },
      prisma,
    );

    return user;
  }

  return currentUser;
};

export const getCurrentUser = async (options: AuthOptions): Promise<User> => {
  const session = await getServerSession(options);
  if (!session) {
    throw new UnauthorizedException("no session");
  }
  const currentUser = await prisma.user.findFirst({
    where: {
      id: session.user.id,
    },
  });

  if (!currentUser) {
    throw new UnauthorizedException(
      `currentUser with id: ${session.user.id} not found`,
    );
  }

  return currentUser;
};

export async function stream2buffer(stream: Stream): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const _buf = Array<any>();

    stream.on("data", (chunk) => _buf.push(chunk));
    stream.on("end", () => resolve(Buffer.concat(_buf)));
    stream.on("error", (err) => reject(`error converting stream - ${err}`));
  });
}

export type ServerSideProps<T> = {
  props: T;
};

export type DTO<T> = T extends bigint
  ? number
  : T extends Prisma.Decimal
    ? number
    : T extends undefined
      ? null
      : T extends Array<infer U>
        ? DTO<U>[]
        : T extends Date
          ? string
          : T extends object
            ? { [K in keyof T]: DTO<T[K]> }
            : T;

export const toDTO = <T>(v: T): DTO<T> => {
  if (v instanceof Date) {
    return v.toISOString() as DTO<T>;
  }

  if (v === undefined) {
    return null as DTO<T>;
  }
  if (v instanceof Array) {
    return v.map((v) => toDTO(v)) as DTO<T>;
  }
  if (typeof v === "bigint") {
    return Number(v) as DTO<T>;
  }
  if (v instanceof Prisma.Decimal) {
    return v.toNumber() as DTO<T>;
  }
  if (typeof v === "object" && v !== null) {
    return Object.fromEntries(
      Object.entries(v).map(([k, v]) => [k, toDTO(v)]),
    ) as DTO<T>;
  }
  return v as DTO<T>;
};

// https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
export const shuffle = <T>(array: T[]): T[] => {
  let currentIndex = array.length,
    randomIndex;

  // While there remain elements to shuffle.
  while (currentIndex != 0) {
    // Pick a remaining element.
    randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    // And swap it with the current element.
    [array[currentIndex], array[randomIndex]] = [
      array[randomIndex],
      array[currentIndex],
    ];
  }

  return array;
};
