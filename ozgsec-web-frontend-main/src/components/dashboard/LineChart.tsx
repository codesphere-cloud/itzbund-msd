import {
  faArrowRight,
  faArrowTrendDown,
  faArrowTrendUp,
  faDownload,
  faExternalLinkAlt,
  faQuestionCircle,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import React, { FunctionComponent, useCallback, useState } from "react";

import { Canvg } from "canvg";
import { debounce } from "lodash";
import { useSearchParams } from "next/navigation";
import {
  VictoryAxis,
  VictoryChart,
  VictoryLine,
  VictoryZoomContainer,
} from "victory";
import useWindowSize from "../../hooks/useWindowSize";
import { InspectionType } from "../../scanner/scans";
import { descriptionMapper, titleMapper } from "../../messages";
import { theme } from "../../styles/victory-theme";
import { linkMapper } from "../../utils/common";
import { tailwindColors } from "../../utils/view";
import CollectionDataPill from "../CollectionDataPill";
import Tooltip from "../common/Tooltip";
import { RefLabelComponent } from "./RefLabelComponent";
import TrendDiff from "./TrendDiff";
import Spinner from "../common/Spinner";

interface Props {
  displayCollections: number[];
  inspectionType: InspectionType;
  data: {
    data: {
      [collectionId: number]:
        | {
            series: { x: string; y: number }[];
            title: string;
            color: string;
          }
        | undefined;
    };
    min: number;
    max: number;
  };
  isGeneratingStats: boolean;
  defaultCollectionId: number;
  zoomLevel: number;
}
const zoomLevelToWidth = (zoomLevel: number, windowWidth: number) => {
  switch (zoomLevel) {
    case 0:
      return 358;
    case 1:
      return 540;
    case 2:
      if (windowWidth === 0) {
        return 890;
      }
      if (windowWidth < 400) {
        return 300;
      }
      if (windowWidth < 600) {
        return 400;
      }
      if (windowWidth < 768) {
        return 540;
      }
      return 890;
    default:
      return 360;
  }
};

const LineChart: FunctionComponent<Props> = ({
  inspectionType,
  data,
  displayCollections,
  defaultCollectionId,
  isGeneratingStats,
  zoomLevel,
}) => {
  const chartRef = React.useRef<any>(null);
  const { width } = useWindowSize();

  const searchParams = useSearchParams();

  const [visibleDomain, setVisibleDomain] = useState<
    [string | undefined, string | undefined]
  >([
    data.data[defaultCollectionId]?.series[0].x,
    data.data[defaultCollectionId]?.series[
      (data.data[defaultCollectionId]?.series.length ?? 0) - 1
    ].x,
  ]);

  const calculateNewTrends = (startIdx: number, endIdx: number) => {
    return Object.fromEntries(
      Object.entries(data.data).map(([collectionId, value]) => {
        if (!value) {
          return [collectionId, { distance: 0 }];
        }
        // calculate the distance from start to beginning
        const start = value.series[startIdx]?.y ?? 0;
        const end = value.series[endIdx]?.y ?? 0;
        const distance = end - start;

        return [
          collectionId,
          {
            distance,
          },
        ];
      }),
    );
  };

  const [trends, setTrends] = useState(
    // calculate the trend over the whole time
    calculateNewTrends(
      0,
      (data.data[defaultCollectionId]?.series.length ?? 0) - 1,
    ),
  );

  const handleDomainChange = useCallback(
    debounce((newDomain: [Date, Date] | [number, number]) => {
      const startIdx = Math.floor(newDomain[0] as number);
      const endIdx = Math.floor(
        Math.min(
          (newDomain[1] as number) - 1,
          (data.data[defaultCollectionId]?.series.length ?? 0) - 1,
        ),
      );

      setTrends(calculateNewTrends(startIdx, endIdx));
      const startX = data.data[defaultCollectionId]?.series[startIdx].x;
      const endX = data.data[defaultCollectionId]?.series[endIdx].x;
      setVisibleDomain([startX, endX]);
    }, 500),
    [data.data, defaultCollectionId],
  );

  const exportToPng = async () => {
    if (chartRef.current) {
      const svg = (
        chartRef.current.containerRef as HTMLDivElement
      ).querySelector("svg");

      if (svg) {
        const clonedNode = svg.cloneNode(true) as SVGSVGElement;

        // add a full size white rect as background color.
        const rect = document.createElementNS(
          "http://www.w3.org/2000/svg",
          "rect",
        );
        rect.setAttribute("width", "100%");
        rect.setAttribute("height", "100%");
        rect.setAttribute("fill", "white");
        clonedNode.insertBefore(rect, clonedNode.firstChild);

        // remove all elements with fill: url(#...)
        const paths = clonedNode.querySelectorAll("path");
        paths.forEach((path) => {
          // remove any shade
          if (
            path.getAttribute("fill")?.startsWith("url") ||
            path.style.fill.startsWith("url")
          ) {
            path.remove();
          } else if (path.style.stroke === "rgb(172, 252, 207)") {
            // primary line
            path.style.stroke = tailwindColors.lightning["900"];
          }
        });

        const lines = clonedNode.querySelectorAll("line");
        lines.forEach((line) => {
          if (line.style.stroke === "rgb(56, 63, 106)") {
            line.style.stroke = "rgb(0, 0, 0)";
          } else if (line.style.stroke === "rgb(203, 213, 225)") {
            // ticks
            line.style.stroke = "rgb(20,20,20)";
          } else if (line.style.stroke === "rgba(255, 255, 255, 0.1)") {
            // grid lines
            line.style.stroke = "rgb(200,200,200)";
          }
        });

        const rects = clonedNode.querySelectorAll("rect");
        rects.forEach((rect) => {
          if (rect.style.fill === "rgb(242, 243, 244)") {
            rect.style.fill = "rgb(255,255,255)";
          }
        });

        // change the font color
        const texts = clonedNode.querySelectorAll("tspan");
        texts.forEach((text) => {
          if (text.style.fill === "rgb(203, 213, 225)") {
            // tick labels
            text.style.fill = "rgb(20, 20, 20)";
          } else if (text.style.fill === "rgb(172, 252, 207)") {
            // axis labels
            text.style.fill = tailwindColors.lightning["900"];
          }
        });

        const canvas = document.createElement("canvas");
        const svgSize = svg.getBoundingClientRect();

        const ctx = canvas.getContext("2d");
        if (!ctx) {
          return;
        }

        // make sure to have the equal size on retina screens
        canvas.width = svgSize.width * (8 / window.devicePixelRatio);
        canvas.height = svgSize.height * (8 / window.devicePixelRatio);
        // add a white background color.
        const serializer = new XMLSerializer();
        const c = Canvg.fromString(
          ctx,
          serializer.serializeToString(clonedNode),
        );
        await c.render();

        // download the image
        const a = document.createElement("a");
        a.href = canvas.toDataURL("image/png");
        a.download = `${titleMapper[inspectionType]}.png`;
        a.click();
      }
    }
  };

  return (
    <div className="group/chart pb-5 text-textblack bg-hellgrau-20 historical-chart flex-col flex">
      <div className="flex-1 pt-5 relative">
        <button
          aria-label="Chart als PNG herunterladen"
          onClick={exportToPng}
          className="group-hover/chart:opacity-100 cursor-pointer z-20 opacity-0 rounded-full text-textblack h-9 absolute top-3 right-3 w-9 text-sm transition-all"
        >
          <FontAwesomeIcon className="opacity-100" icon={faDownload} />
        </button>
        {isGeneratingStats && (
          <div className="absolute top-0 text-base left-0 w-full h-full flex flex-row items-center justify-center bg-hellgrau-20 opacity-75 z-10">
            <div className="text-center">
              <div className="flex flex-row justify-center">
                <Spinner size={40} />
              </div>
              <div className="mt-2">
                Statistiken werden generiert. Dies kann einige Minuten dauern.
              </div>
            </div>
          </div>
        )}

        <VictoryChart
          containerComponent={
            <VictoryZoomContainer
              portalZIndex={10}
              allowZoom={searchParams?.get("zoomable") === "1"}
              onZoomDomainChange={(ev) => handleDomainChange(ev.x)}
              ref={chartRef}
            />
          }
          theme={theme}
          height={360}
          width={zoomLevelToWidth(zoomLevel, width)}
          padding={{ top: 20, bottom: 40, left: 55, right: 10 }}
          minDomain={{ y: Math.max(-1, data.min - data.max / 20) }}
          maxDomain={{ y: Math.min(101.5, data.max + data.max / 20) }}
          domainPadding={{ x: [0, 35], y: [100, 100] }}
        >
          <defs>
            <linearGradient x2="0%" y2="100%" id="serviceGradient">
              <stop offset="0%" stopColor={"rgba(172,252,207,0.2)"} />
              <stop offset="100%" stopColor="rgba(0,0,0,0)" />
            </linearGradient>
          </defs>
          <VictoryAxis fixLabelOverlap />
          <VictoryAxis
            tickFormat={(t: any) => `${t}%`}
            dependentAxis
            domain={{ y: [-10, 1000] }}
            fixLabelOverlap
          />
          {displayCollections.map((collectionId, i, arr) => {
            const d = data.data[collectionId];
            if (!d) return null;
            const color =
              +collectionId === defaultCollectionId
                ? tailwindColors.blau["100"]
                : d.color;

            return (
              <VictoryLine
                key={collectionId}
                style={{
                  data: {
                    strokeLinecap: "round",
                    stroke: color,
                  },
                }}
                //  interpolation={"basis"}
                labels={(label: any) => {
                  if (+label.index === d.series.length - 1) {
                    return `${label.datum.y.toFixed(1)}%`;
                  }
                  return d.title;
                }}
                labelComponent={
                  <RefLabelComponent
                    fill={color}
                    nRefComponents={arr.length}
                    i={i}
                  />
                }
                data={d.series}
              />
            );
          })}
        </VictoryChart>
      </div>
      <h2
        title={titleMapper[inspectionType]}
        className="text-left px-6 text-lg flex flex-row items-center text-ellipsis font-bold mt-1"
      >
        {titleMapper[inspectionType]}{" "}
        <Tooltip
          tooltip={
            <>
              <p className="mb-4">{descriptionMapper[inspectionType]}</p>
              {linkMapper[inspectionType] !== "" && (
                <a
                  download
                  target={"_blank"}
                  href={linkMapper[inspectionType]}
                  rel="noreferrer"
                >
                  &quot;{titleMapper[inspectionType]}&quot; One-Pager
                  herunterladen
                  <FontAwesomeIcon
                    fontSize={15}
                    className="ml-2"
                    icon={faExternalLinkAlt}
                  />
                </a>
              )}
            </>
          }
        >
          <div className="text-dunkelgrau-100 inline ml-2">
            <FontAwesomeIcon fontSize={18} icon={faQuestionCircle} />
          </div>
        </Tooltip>
      </h2>
      <div>
        <div className="opacity-75 text-sm px-6">
          {visibleDomain[0]} - {visibleDomain[1]}
        </div>
      </div>
      <div className="flex flex-row items-center flex-wrap mt-2 gap-2 px-6">
        {displayCollections.map((collectionId) => {
          const col = data.data[collectionId];
          const trend = trends[collectionId];
          if (!col || !trend) return null;

          return (
            <CollectionDataPill
              key={collectionId}
              color={col.color}
              title={col.title}
            >
              <div className="text-sm mr-2">{col.title}</div>
              <span className="text-sm">
                {trend.distance === 0 ? "" : trend.distance > 0 ? "+" : ""}
              </span>
              <span className="text-sm">{trend.distance.toFixed(1)} %P</span>
              <FontAwesomeIcon
                className="text-sm ml-2"
                icon={
                  trend.distance === 0
                    ? faArrowRight
                    : trend.distance > 0
                      ? faArrowTrendUp
                      : faArrowTrendDown
                }
              />
            </CollectionDataPill>
          );
        })}
      </div>
      {searchParams?.get("displayDiff") === "1" && (
        <div className="px-6 mt-5">
          <TrendDiff
            inspectionType={inspectionType}
            start={visibleDomain[0]}
            end={visibleDomain[1]}
            displayCollections={displayCollections}
          />
        </div>
      )}
    </div>
  );
};

export default LineChart;
