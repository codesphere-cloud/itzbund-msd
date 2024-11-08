import { DomainInspectionType } from "../scanner/scans";
import { getSUTFromResponse } from "../services/sarifTransformer";
import { DetailedTarget, ISarifResponse } from "../types";
import { DTO } from "../utils/server";

export const getCAAReportMessage = (report: DTO<ISarifResponse> | null) => {
  if (report === null) {
    return "Die Überprüfung nach CAA Einträgen konnte nicht durchgeführt werden.";
  }
  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === DomainInspectionType.CAA,
  );
  const uri = getSUTFromResponse(report);
  if (
    inspection === null ||
    inspection === undefined ||
    inspection.kind === "notApplicable"
  ) {
    return `Die Überprüfung nach CAA Einträgen für die Domain ${uri} konnte nicht durchgeführt werden.`;
  } else if (inspection.kind === "pass") {
    return `CAA Einträge sind für die Domain ${uri} eingerichtet.`;
  } else {
    return `Es wurden keine CAA Einträge für die Domain ${uri} gefunden.`;
  }
};
