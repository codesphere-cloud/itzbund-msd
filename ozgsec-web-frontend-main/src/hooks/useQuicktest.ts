import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { getErrorMessage } from "../messages/http";
import { clientHttpClient } from "../services/clientHttpClient";
import { ISarifResponse, TestAmount } from "../types";
import { sanitizeURI } from "../utils/common";
import { DTO } from "../utils/server";
import useLoading from "./useLoading";

const isInViewport = (element: HTMLElement) => {
  const rect = element.getBoundingClientRect();
  return (
    rect.top >= 0 &&
    rect.left >= 0 &&
    rect.bottom <=
      (window.innerHeight || document.documentElement.clientHeight) &&
    rect.right <= (window.innerWidth || document.documentElement.clientWidth)
  );
};

export function useQuicktest(code?: string | null) {
  const [website, setWebsite] = useState("");
  const scanRequest = useLoading();
  const refreshRequest = useLoading();
  const [report, setReport] = useState<null | DTO<ISarifResponse>>(null);
  const router = useRouter();
  const query = useSearchParams();
  const pathname = usePathname();

  const onSubmit = useCallback(
    async (e: FormEvent, site: string) => {
      e.preventDefault();

      // test if valid url
      const target = sanitizeURI(site);
      if (!target) {
        scanRequest.error("Bitte trage einen gültigen Domainnamen ein.");
        return;
      }
      // react will batch those two calls anyways.
      scanRequest.loading();
      setReport(null);
      // do the real api call.
      // forward the secret of query param s to the backend
      try {
        const response = await clientHttpClient(
          `/api/v2/scan?site=${encodeURIComponent(
            target,
          )}&s=${code}&refresh=${query.get("refresh")}`,
          crypto.randomUUID(),
        );
        if (!response.ok) {
          const err = await response.json();

          return scanRequest.error(
            `Es ist ein Fehler aufgetreten - Fehlermeldung: ${getErrorMessage(
              err.errorMessage,
            )}`,
          );
        }
        const obj: DTO<ISarifResponse> = await response.json();
        setReport(obj);
        scanRequest.success();
      } catch (e) {
        scanRequest.error(
          "Es ist ein Fehler aufgetreten. Bitte versuche es später erneut.",
        );
      }
    },
    [scanRequest, code],
  );
  useEffect(() => {
    if (report) {
      const rec = document.getElementById("test-results");
      if (rec && !isInViewport(rec)) {
        window.scrollTo({
          top:
            rec.getBoundingClientRect().top +
            window.scrollY -
            window.innerHeight / 16,
          behavior: "smooth",
        });
      }
    }
  }, [report]);

  const scannedSite = useRef<null | string>(null);

  useEffect(() => {
    const site = query?.get("site");
    if (site && scannedSite.current !== site) {
      scannedSite.current = site;
      setWebsite(site);
      onSubmit(
        {
          preventDefault: () => {},
        } as FormEvent,
        query?.get("site") as string,
      );
    }
  }, [query, onSubmit]);

  const handleRefresh = async () => {
    if (!report) {
      return;
    }
    refreshRequest.loading();

    try {
      const response = await clientHttpClient(
        `/api/v2/scan?site=${encodeURIComponent(
          report.runs[0].properties.target,
        )}&refresh=true&s=${code}`,
        crypto.randomUUID(),
      );
      if (!response.ok) {
        const err = await response.json();
        return refreshRequest.error(
          `Es ist ein Fehler aufgetreten - Fehlermeldung: ${getErrorMessage(
            err.errorMessage,
          )}`,
        );
      }
      const obj = await response.json();
      setReport(obj);
      refreshRequest.success();
    } catch (e) {
      refreshRequest.error(
        "Es ist ein Fehler aufgetreten. Bitte versuche es später erneut.",
      );
    }
  };

  const testAmount: TestAmount = useMemo((): TestAmount => {
    if (!report) return { passed: 0, total: 0 };
    const results = report?.runs[0].results;
    return {
      passed: (results ?? []).filter((r) => r.kind === "pass").length,
      total: results.length,
    };
  }, [report]);

  const dateString = report
    ? new Date(report.runs[0].invocations[0].startTimeUtc).toLocaleString()
    : "";

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const searchParams = new URLSearchParams({
      ...Object.fromEntries((query ?? new URLSearchParams()).entries()),
      site: website,
    });
    router.push(`${pathname}?${searchParams.toString()}`);
  };

  return {
    website,
    setWebsite,
    onSubmit: handleSubmit,
    scanRequest,
    refreshRequest,
    report,
    handleRefresh,
    testAmount,
    dateString,
  };
}
