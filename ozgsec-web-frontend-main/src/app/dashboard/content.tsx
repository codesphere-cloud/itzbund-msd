"use client";

import {
  faCircleInfo,
  faQuestionCircle,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import {
  FunctionComponent,
  useEffect,
  useMemo,
  useState,
  useTransition,
} from "react";
import EmptyDashboardNotice from "../../components/EmptyDashboardNotice";
import PageTitle from "../../components/PageTitle";
import Tooltip from "../../components/common/Tooltip";
import PieCharts from "../../components/dashboard/PieCharts";
import useGeneratingStatsPoll from "../../hooks/useGeneratingStatsPoll";
import useRefreshOnVisit from "../../hooks/useRefreshOnVisit";
import { ChartData, FeatureFlag, IDashboard } from "../../types";
import { classNames } from "../../utils/common";
import { useIsFeatureEnabled } from "../../hooks/useFeatureEnabled";
import CollectionPill from "../../components/CollectionPill";
import { tailwindColors } from "../../utils/view";
import { useGlobalStore } from "../../zustand/global";

import { DTO } from "../../utils/server";
import { Collection } from "@prisma/client";

interface Props {
  dashboard: IDashboard;
  defaultCollectionId: number;
  refCollections: number[];
  collections: { [id: number]: DTO<Collection> & { size: number } };
}

const Content: FunctionComponent<Props> = (props) => {
  useRefreshOnVisit("dashboard");

  const dashboard = props.dashboard;
  const currentStat = useMemo(
    () =>
      props.defaultCollectionId in dashboard.historicalData
        ? dashboard.historicalData[props.defaultCollectionId]!.series[
            dashboard.historicalData[props.defaultCollectionId]!.series.length -
              1
          ]
        : ({
            totalCount: 0,
            data: {},
          } as ChartData),
    [dashboard.historicalData, props.defaultCollectionId],
  );

  const [displayCollections, setDisplayCollections] = useState(
    props.refCollections.concat(props.defaultCollectionId),
  );

  const { session } = useGlobalStore();

  const [_, startTransition] = useTransition();
  const [_displayCollections, _setDisplayCollections] = useState(
    props.refCollections.concat(props.defaultCollectionId),
  );

  const [data, setData] = useState({
    totalCount: currentStat.totalCount,
    data: Object.fromEntries(
      Object.keys(currentStat.data).map((key) => [key, 0]),
    ),
  });

  const noDomains = dashboard.totals.uniqueTargets === 0;

  const isGeneratingStats = useGeneratingStatsPoll(
    dashboard.historicalData[props.defaultCollectionId]?.series.length,
  );

  const collectionsEnabled = useIsFeatureEnabled(FeatureFlag.collections);

  const handleDisplayCollectionToggle = (collectionId: number) => {
    if (displayCollections.includes(collectionId)) {
      // check if there is at least one collection left
      if (displayCollections.length === 1) {
        setDisplayCollections([props.defaultCollectionId]);
        startTransition(() => {
          _setDisplayCollections([props.defaultCollectionId]);
        });
        return;
      }
      setDisplayCollections((prev) => prev.filter((id) => id !== collectionId));
      startTransition(() => {
        _setDisplayCollections((prev) =>
          prev.filter((id) => id !== collectionId),
        );
      });
    } else {
      setDisplayCollections((prev) => prev.concat(collectionId));
      startTransition(() => {
        _setDisplayCollections((prev) => prev.concat(collectionId));
      });
    }
  };

  useEffect(() => {
    setData(currentStat);
  }, [currentStat]);
  return (
    <>
      <div className="mb-0 gap-2 flex flex-row items-center">
        <PageTitle className="text-2xl  font-bold" stringRep="Dashboard">
          Dashboard
        </PageTitle>
        <Tooltip
          tooltip={`         
      Das Dashboard bietet eine Übersicht über den Sicherheitszustand von Domain-Gruppen.`}
        >
          <div className="text-dunkelgrau-100">
            <FontAwesomeIcon icon={faQuestionCircle} />
          </div>
        </Tooltip>
      </div>
      {collectionsEnabled && (
        <div className=" sticky z-20 bg-white border-b-6 border-hellgrau-40 beneath-header py-2 flex flex-row mb-4 items-center">
          <div className="text-lg gap-1 flex flex-col flex-1 mx-auto">
            <span className="font-semibold">
              Domain-Gruppe (Anzahl der Domains)
            </span>
            <div className="flex flex-wrap flex-row gap-2 items-center justify-start">
              {Object.values(props.collections).map((col) => {
                // check if selected
                const selected = displayCollections.includes(col.id);

                return (
                  <CollectionPill
                    onClick={() => {
                      handleDisplayCollectionToggle(col.id);
                    }}
                    selected={selected}
                    key={col.id}
                    {...col}
                    title={
                      col.id === props.defaultCollectionId
                        ? `${session?.user.name || "Meine"} (${col.size})`
                        : `${col.title} (${col.size})`
                    }
                    color={
                      col.id === props.defaultCollectionId
                        ? tailwindColors.blau["100"]
                        : col.color
                    }
                  />
                );
              })}
            </div>
          </div>
        </div>
      )}

      <div className={classNames(noDomains && "relative pointer-events-none")}>
        <div
          className={classNames(
            "max-w-screen-2xl pb-10 mx-auto flex-1 ",
            noDomains && "blur-sm overflow-hidden",
          )}
          style={{
            maxHeight: noDomains ? "calc(100vh)" : "auto",
          }}
        >
          <PieCharts
            isGeneratingStats={isGeneratingStats}
            displayCollections={displayCollections}
            historicalData={dashboard.historicalData}
            defaultCollectionId={props.defaultCollectionId}
            currentStat={data as ChartData}
          />
        </div>
        {noDomains && (
          <div className="absolute pointer-events-auto z-90 mt-10 top-0 flex flex-row justify-center left-0 right-0 mb-10 px-3 flex-1">
            <div className="p-5 pb-12 flex flex-row rounded-sm bg-hellgrau-60 max-w-screen-lg text-textblack">
              <div className="pr-3 pt-1">
                <FontAwesomeIcon size={"lg"} icon={faCircleInfo} />
              </div>
              <EmptyDashboardNotice />
            </div>
          </div>
        )}
      </div>
    </>
  );
};

export default Content;
