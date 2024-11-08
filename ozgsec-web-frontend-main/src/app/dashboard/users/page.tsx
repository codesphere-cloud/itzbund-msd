import UserRepresentation from "@keycloak/keycloak-admin-client/lib/defs/userRepresentation";
import { Stat, User } from "@prisma/client";
import { cookies } from "next/dist/client/components/headers";
import { redirect } from "next/navigation";
import { prisma } from "../../../db/connection";
import { InspectionType } from "../../../scanner/scans";
import { collectionService } from "../../../services/collectionService";
import { keycloak } from "../../../services/keycloak";
import { statService } from "../../../services/statService";
import { userService } from "../../../services/userService";
import { isAdmin } from "../../../utils/common";
import { getJWTToken } from "../../../utils/server";
import { displayInspections } from "../../../utils/view";
import Content from "./content";

const Page = async () => {
  const token = await getJWTToken({
    req: { cookies: cookies() },
  } as any);

  // check if the user is an admin
  // if not, redirect him to the dashboard page.
  if (!isAdmin(token) || !token) {
    return redirect("/dashboard");
  }

  // fetch all users from keycloak
  const kcAdminClient = keycloak.getKcAdminClient(token.accessToken);

  let props: {
    error: boolean;
    users: Array<
      UserRepresentation &
        User & { id: string; targetsCount: number; totalImprovements: number }
    >;
  };
  try {
    const [kcUsers, usersFromDB, collectionAggregate] = await Promise.all([
      kcAdminClient.users.find(),
      userService.getAll(prisma),
      collectionService.countTargetsInCollections(prisma),
    ]);

    const stats = (
      await Promise.all(
        usersFromDB.map((u) =>
          statService.getLatestAndEarliestStats(u, prisma),
        ),
      )
    ).reduce(
      (acc, curr, i) => {
        acc[usersFromDB[i].id.toString()] = curr;
        return acc;
      },
      {} as Record<string, { firstStat: Stat | null; lastStat: Stat | null }>,
    );

    // attach the networks to the kc users.
    props = {
      error: false,
      users: kcUsers
        .map((user): [UserRepresentation, User | undefined] => [
          user,
          usersFromDB.find((userFromDB) => userFromDB.id === user.id),
        ])
        .filter(
          (params): params is [UserRepresentation, User] =>
            params[1] !== undefined,
        )
        .map(([user, userFromDB]) => {
          return {
            ...user,
            id: user.id as string,
            defaultCollectionId: userFromDB.defaultCollectionId,
            featureFlags: userFromDB.featureFlags,
            targetsCount:
              collectionAggregate[userFromDB.defaultCollectionId] ?? 0,
            totalImprovements: displayInspections
              .map((inspection) => {
                // calculate the first amount of domains and the last
                const firstStatValue = stats[userFromDB.id.toString()].firstStat
                  ?.value as {
                  totalCount: number;
                  data: Record<InspectionType, number>;
                } | null;

                const lastStatValue = stats[userFromDB.id.toString()].lastStat
                  ?.value as {
                  totalCount: number;
                  data: Record<InspectionType, number>;
                } | null;
                if (
                  !firstStatValue ||
                  !lastStatValue ||
                  !lastStatValue.data[inspection] ||
                  !firstStatValue.data[inspection]
                ) {
                  return 0;
                }

                // calculate the difference between the first and the last
                return Math.round(
                  Math.round(
                    lastStatValue.data[inspection] * lastStatValue.totalCount,
                  ) -
                    Math.round(
                      firstStatValue.data[inspection] *
                        firstStatValue.totalCount,
                    ),
                );
              })
              .reduce((acc, curr) => acc + Math.max(curr, 0), 0),
          };
        }),
    };
  } catch (e) {
    // log the user out and redirect to keycloak
    props = {
      error: true,
      users: [],
    };
  }
  return <Content {...props} />;
};

export default Page;
