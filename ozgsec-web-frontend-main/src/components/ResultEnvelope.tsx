import { faRefresh } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { toUnicode } from "punycode";
import { FunctionComponent } from "react";
import { legendMessages } from "../messages/legend";
import { ISarifResponse, TestAmount } from "../types";
import { classNames } from "../utils/common";
import {
  CheckResult,
  checkResult2BorderClassName,
  checkResult2Icon,
} from "../utils/view";
import ResultGrid from "./ResultGrid";
import Button from "./common/Button";
import { getSUTFromResponse } from "../services/sarifTransformer";
import { featureFlags } from "../feature-flags";

interface Props {
  report: ISarifResponse | null;
  dateString: string;
  handleRefresh: () => Promise<void>;
  refreshRequest: {
    loading: (key?: string) => void;
    success: () => void;
    error: (err: string, key?: string) => void;
    isLoading: boolean;
    errorMessage: string;
    errored: boolean;
    key: string;
    successed: boolean;
  };
  testAmount: TestAmount;
}

const ResultEnvelope: FunctionComponent<Props> = ({
  report,
  dateString,
  handleRefresh,
  refreshRequest,
  testAmount,
}) => {
  const sut = getSUTFromResponse(report) ?? "";
  const { refreshEnabled } = featureFlags;
  return report !== null ? (
    <div className="md:p-0 text-textblack">
      <div className="md:flex block mb-5 gap-5 flex-row justify-between">
        <div className="md:w-2/3">
          <h2 id="test-results" className="text-xl">
            Testergebnisse für{" "}
            <a
              target={"_blank"}
              className="text-blau-100"
              rel="noopener noreferrer"
              href={`//${toUnicode(report.runs[0].properties.target)}`}
            >
              {toUnicode(report.runs[0].properties.target)}{" "}
            </a>
          </h2>
          {report.runs[0].properties.target !== sut && (
            <h2 className="text-xl">
              Weiterleitung auf:{" "}
              <a
                target={"_blank"}
                className="underline text-blau-100"
                rel="noopener noreferrer"
                href={`//${toUnicode(sut)}`}
              >
                {toUnicode(sut)}
              </a>
            </h2>
          )}
          <div className="flex-wrap mt-4 justify-between flex-row">
            <div className="flex-1">
              <div className="flex gap-3 items-center flex-row">
                <p>{dateString.substring(0, dateString.length - 3)}</p>
                {refreshEnabled && (
                  <Button
                    onClick={handleRefresh}
                    title="Testergebnisse aktualisieren"
                  >
                    <FontAwesomeIcon
                      className={refreshRequest.isLoading ? "rotate" : ""}
                      icon={faRefresh}
                    />
                  </Button>
                )}
              </div>
              <p>
                Erfüllt: {testAmount.passed}/{testAmount.total}
              </p>
            </div>
          </div>
        </div>

        <div className="md:w-1/3 md:px-4 text-textblack">
          <div className="flex-row flex items-center">
            <FontAwesomeIcon
              className={`text-${checkResult2BorderClassName(
                CheckResult.Passed,
              )} text-2xl w-8`}
              icon={checkResult2Icon(CheckResult.Passed)}
            />
            <span className="ml-4">{legendMessages(CheckResult.Passed)}</span>
          </div>
          <div className="flex-row flex items-center">
            <FontAwesomeIcon
              className={`text-${checkResult2BorderClassName(
                CheckResult.Failed,
              )} text-2xl w-8`}
              icon={checkResult2Icon(CheckResult.Failed)}
            />
            <span className="ml-4">{legendMessages(CheckResult.Failed)}</span>
          </div>
          <div className="flex-row flex items-center">
            <div className="w-8 flex flex-row items-center">
              <FontAwesomeIcon
                className={`text-${checkResult2BorderClassName(
                  CheckResult.Critical,
                )} text-2xl w-8`}
                icon={checkResult2Icon(CheckResult.Critical)}
              />
            </div>
            <span className="ml-4">{legendMessages(CheckResult.Critical)}</span>
          </div>
        </div>
      </div>
      {!refreshRequest.isLoading && !refreshRequest.errored && (
        <div>
          <ResultGrid report={report} />
        </div>
      )}
      {refreshRequest.errored && (
        <div>
          <p className={classNames("text-red-500")}>
            {refreshRequest.errorMessage}
          </p>
        </div>
      )}
    </div>
  ) : (
    <></>
  );
};

export default ResultEnvelope;
