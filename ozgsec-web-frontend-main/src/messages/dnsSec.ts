import { DomainInspectionType } from "../scanner/scans";
import { getSUTFromResponse } from "../services/sarifTransformer";
import { ISarifResponse } from "../types";
import { getUnicodeHostnameFromUri } from "../utils/common";
import { DTO } from "../utils/server";

export const getDNSSecReportMessage = (report: DTO<ISarifResponse> | null) => {
  if (report === null) {
    return "DNSSEC konnte nicht überpüft werden.";
  }
  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === DomainInspectionType.DNSSec,
  );
  const hostname = getUnicodeHostnameFromUri(
    getSUTFromResponse(report) as string,
  );
  if (!inspection || inspection?.kind === "notApplicable") {
    return `DNSSEC konnte für die Domain ${hostname} nicht überprüft werden.`;
  } else if (inspection.kind === "pass") {
    return `DNSSEC ist für die Domain ${hostname} eingerichtet.`;
  } else {
    return `DNSSEC ist für die Domain ${hostname} nicht eingerichtet.`;
  }
};
