import { useRouter } from "next/navigation";
import { useEffect } from "react";

const refreshMap = new Map<string, boolean>();

export default function useRefreshOnVisit(id: string) {
  const router = useRouter();
  useEffect(() => {
    if (refreshMap.get(id)) {
      router.refresh();
    } else {
      // initial call
      refreshMap.set(id, true);
    }
  }, []);
}
