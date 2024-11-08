"use client";

import { faCaretDown } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import { FunctionComponent, useEffect, useRef, useState } from "react";
import useLoading from "../../hooks/useLoading";
import { clientHttpClient } from "../../services/clientHttpClient";
import { classNames } from "../../utils/common";
import { kind2CheckResult } from "../../utils/view";
import ResultIcon from "../ResultIcon";
import Spinner from "../common/Spinner";
import { useSearchParams } from "next/navigation";
import { didPass2Kind } from "../../services/sarifTransformer";

const parseDate = (date: string) => {
  let [day, month, year] = date.split(".");
  if (year.length === 2) {
    year = `20${year}`;
  }
  return new Date(`${year}-${month}-${day}`);
};

interface DiffConfig {
  inspectionType: string;
  start: string;
  end: string;
  collectionIds: number[];
}

const configChange = (a: DiffConfig, b: DiffConfig) => {
  return (
    a.inspectionType !== b.inspectionType ||
    a.start !== b.start ||
    a.end !== b.end ||
    a.collectionIds.length !== b.collectionIds.length ||
    a.collectionIds.some((id, i) => id !== b.collectionIds[i])
  );
};

interface Props {
  displayCollections: number[];
  start?: string;
  end?: string;
  inspectionType: string;
}
const TrendDiff: FunctionComponent<Props> = ({
  displayCollections,
  start,
  end,
  inspectionType,
}) => {
  const lastFetchConfig = useRef<DiffConfig>({
    inspectionType: "",
    start: "",
    end: "",
    collectionIds: [],
  });

  const searchParams = useSearchParams();

  const [isOpen, setIsOpen] = useState(false);

  const diffRequest = useLoading();

  const [diff, setDiff] = useState<{
    true: { uri: string; was: boolean; now: boolean }[];
    false: { uri: string; was: boolean; now: boolean }[];
  }>({
    true: [],
    false: [],
  });

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const updateDiff = async ({
    start,
    end,
    collectionIds,
    inspectionType,
  }: DiffConfig) => {
    // transform start and end to unix timestamp
    diffRequest.loading();
    const url = new URLSearchParams({
      start: parseDate(start).getTime().toString(),
      end: parseDate(end).getTime().toString(),
      collectionIds: collectionIds.map((id) => id.toString()).join(","),
      inspectionType,
      forceCollection:
        (searchParams?.get("forceCollection") as string | undefined) ?? "",
    }).toString();
    const res = await clientHttpClient(
      `/api/v1/diff?${url}`,
      crypto.randomUUID(),
    );
    const diff: {
      false: Array<{ uri: string; was: boolean; now: boolean }>;
      true: Array<{ uri: string; was: boolean; now: boolean }>;
    } = await res.json();
    setDiff(diff);
    diffRequest.success();
  };

  useEffect(() => {
    if (start && end && isOpen) {
      const config = {
        inspectionType,
        start,
        end,
        collectionIds: displayCollections,
      };
      if (configChange(lastFetchConfig.current, config)) {
        lastFetchConfig.current = config;
        updateDiff(config);
      }
    }
  }, [start, end, displayCollections, inspectionType, updateDiff, isOpen]);

  return (
    <div className="flex-col flex gap-2">
      <div>
        <a
          className="text-sm underline"
          role="button"
          onClick={() => setIsOpen((prev) => !prev)}
        >
          {isOpen ? "Änderungen ausblenden" : "Änderungen anzeigen"}{" "}
          <FontAwesomeIcon
            className={classNames("transition-all", isOpen && "rotate-180")}
            icon={faCaretDown}
          />
        </a>
      </div>
      <div className="flex gap-2 flex-col">
        {isOpen && (
          <>
            {diffRequest.isLoading ? (
              <div className="flex flex-row gap-3 items-center">
                <Spinner />
              </div>
            ) : (
              <>
                {["true", "false"].map((key) => (
                  <div className="flex flex-wrap gap-2" key={key}>
                    {diff[key as "true" | "false"]?.map((d) => {
                      return (
                        <div
                          className="rounded-full text-sm border-2 border-deepblue-50 px-2 py-1 flex flex-row items-center gap-2"
                          key={d.uri}
                        >
                          <span>
                            <ResultIcon
                              size={16}
                              checkResult={kind2CheckResult(
                                didPass2Kind(d.now),
                              )}
                            />
                          </span>
                          <span>{d.uri}</span>
                        </div>
                      );
                    })}
                  </div>
                ))}
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default TrendDiff;
