import { FunctionComponent } from "react";

import { InspectionType } from "../../scanner/scans";
import { classNames } from "../../utils/common";
import LineChart from "./LineChart";

interface Props {
  displayCollections: number[];
  displayInspections: InspectionType[];
  dataPerInspection: {
    [key: string]: {
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
  };
  isGeneratingStats: boolean;
  defaultCollectionId: number;
  zoomLevel: number;
}

const LineCharts: FunctionComponent<Props> = ({
  displayCollections,
  displayInspections,
  dataPerInspection,
  isGeneratingStats,
  defaultCollectionId,
  zoomLevel,
}) => {
  return (
    <div>
      <div>
        <div
          style={{
            gridTemplateColumns: `repeat(${3 - zoomLevel}, 1fr)`,
          }}
          className={classNames("grid gap-3 justify-start")}
        >
          {displayInspections.map((key) => {
            return (
              <LineChart
                key={key}
                isGeneratingStats={isGeneratingStats}
                zoomLevel={zoomLevel}
                inspectionType={key}
                displayCollections={displayCollections}
                defaultCollectionId={defaultCollectionId}
                data={dataPerInspection[key]}
              />
            );
          })}
        </div>
      </div>
      <div></div>
    </div>
  );
};

export default LineCharts;
