import { FunctionComponent } from "react";

import {
  AccessiblityInspectionType,
  CertificateInspectionType,
  DomainInspectionType,
  HeaderInspectionType,
  NetworkInspectionType,
  OrganizationalInspectionType,
  TLSInspectionType,
} from "../scanner/scans";
import { ISarifResponse } from "../types";
import { classNames, devOnly, linkMapper } from "../utils/common";
import {
  CheckResult,
  checkResult2BorderClassName,
  kind2CheckResult,
} from "../utils/view";

import { getCheckDescription, titleMapper } from "../messages";
import { DTO } from "../utils/server";
import ResultBox from "./ResultBox";

const regularChecks = [
  OrganizationalInspectionType.ResponsibleDisclosure,
  TLSInspectionType.TLSv1_3,
  TLSInspectionType.DeprecatedTLSDeactivated,
  HeaderInspectionType.HSTS,
  DomainInspectionType.DNSSec,
  NetworkInspectionType.RPKI,

  AccessiblityInspectionType.ProvidesEnglishWebsiteVersion,
] as const;

const immediateActionRequired = [
  CertificateInspectionType.MatchesHostname,
  CertificateInspectionType.ValidCertificate,
] as const;

type ImmediateActions = typeof immediateActionRequired;

const shouldDisplayImmediateActionRequired = (
  report: DTO<ISarifResponse>,
  check: ImmediateActions[number],
): boolean => {
  if (report === null) {
    return false;
  }
  const result = report.runs[0].results.find((r) => r.ruleId === check);
  return result?.kind === "fail";
};

interface Props {
  report: DTO<ISarifResponse>;
}

const ResultGrid: FunctionComponent<Props> = (props) => {
  const { report } = props;

  const immediateActionRequiredChecks = immediateActionRequired.filter((key) =>
    shouldDisplayImmediateActionRequired(report, key),
  );
  return (
    <>
      {devOnly(() => (
        <>
          {immediateActionRequiredChecks.length > 0 && (
            <div className="mt-3 mb-4 flex flex-wrap flex-row gap-4">
              {immediateActionRequiredChecks.map((key) => {
                return (
                  <div key={key} className="w-full flex-none sm:flex-1">
                    <div
                      className={classNames(
                        "bg-dunkelblau-20 border-2 h-full rounded-sm p-5",
                        `border-${checkResult2BorderClassName(
                          CheckResult.Critical,
                        )}`,
                      )}
                    >
                      <ResultBox
                        title={titleMapper[key]}
                        description={getCheckDescription(report, key)}
                        link={linkMapper[key]}
                        checkResult={CheckResult.Critical}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </>
      ))}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 mt-3 gap-4">
        {regularChecks.map((key) => {
          return (
            <div key={key} className="">
              <div
                className={classNames(
                  "bg-dunkelblau-20/40 h-full p-5",
                  /* `border-${checkResult2BorderClassName(
                    didPass2CheckResult(
                      report.details !== null
                        ? report.details[key]?.didPass
                        : null
                    )
                  )}`*/
                )}
              >
                <ResultBox
                  title={titleMapper[key]}
                  description={getCheckDescription(report, key)}
                  link={linkMapper[key]}
                  checkResult={kind2CheckResult(
                    report !== null
                      ? report.runs[0].results.find((r) => r.ruleId === key)
                          ?.kind
                      : null,
                  )}
                />
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
};

export default ResultGrid;
