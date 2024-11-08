import { useSession as baseUseSession } from "next-auth/react";
import { ISession } from "../types";
import { featureFlags } from "../feature-flags";
export function useSession() {
  if (!featureFlags.dashboardEnabled) {
    return baseUseSession() as {
      data: ISession | undefined | null;
      status: string;
    };
  } else return { data: undefined, status: "" };
}
