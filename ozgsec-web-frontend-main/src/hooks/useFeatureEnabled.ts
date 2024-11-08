import { User } from "@prisma/client";
import { FeatureFlag } from "../types";
import { isFeatureEnabled, isGuestUser } from "../utils/common";
import { useGlobalStore } from "../zustand/global";

export function useIsFeatureEnabled(featureFlag: FeatureFlag) {
  const { user } = useGlobalStore();
  if (!user || isGuestUser(false)) return false;

  return isFeatureEnabled(featureFlag, user as User);
}
