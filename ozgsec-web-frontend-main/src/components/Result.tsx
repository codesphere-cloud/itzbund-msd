import { faCheckCircle, faTimes } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import React, { FunctionComponent } from "react";
import { classNames } from "../utils/common";

interface Props {
  didPass?: boolean;
  subtitle: string;
  Inspection?: React.ReactNode;
}

const Result: FunctionComponent<Props> = (props) => {
  return (
    <div className="flex flex-row">
      <div className="bg-deepblue-300 p-4 -ml-3 mr-9">
        <div className={classNames("flex flex-row items-center")}>
          <FontAwesomeIcon
            className={props.didPass ? "text-lightning-500" : "text-red-500"}
            fontSize={35}
            icon={props.didPass ? faCheckCircle : faTimes}
          />
          <div className="ml-5">
            <h2
              className={classNames(
                props.didPass ? "text-lightning-500" : "text-red-500",
                "text-xl font-bold",
              )}
            >
              {props.didPass ? "Test bestanden" : "Test fehlgeschlagen"}
            </h2>
            <p>{props.subtitle}</p>
          </div>
        </div>
      </div>
      <div className="p-4">
        <div className="w-64" />
      </div>
    </div>
  );
};

export default Result;
