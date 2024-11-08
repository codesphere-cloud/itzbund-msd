import { isGuestUser } from "../utils/common";
import { useGlobalStore } from "../zustand/global";

export function useIsGuest() {
  const { session } = useGlobalStore();
  return isGuestUser(session?.user);
}
