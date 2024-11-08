import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef } from "react";
import { diffDays } from "../utils/view";

export default function useGeneratingStatsPoll(
  seriesLength: number | undefined,
) {
  const router = useRouter();
  const pollInterval = useRef<any>(null);
  const expectedSeriesLength = useMemo(
    () => diffDays(new Date(2023, 0, 15), new Date()),
    [],
  );
  const isGeneratingStats = expectedSeriesLength > (seriesLength ?? 0);

  useEffect(() => {
    if (isGeneratingStats && !pollInterval.current) {
      pollInterval.current = setInterval(() => {
        router.refresh();
      }, 5000);
    }
    if (!isGeneratingStats && pollInterval) {
      clearInterval(pollInterval.current);
      pollInterval.current = null;
    }
  }, [isGeneratingStats]);

  return isGeneratingStats;
}
