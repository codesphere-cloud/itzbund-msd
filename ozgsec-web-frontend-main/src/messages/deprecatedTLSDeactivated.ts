import { TLSInspectionType } from "../scanner/scans";
import { ISarifResponse } from "../types";
import { DTO } from "../utils/server";

export const getDeprecatedTLSDeactivatedReportMessage = (
  report: DTO<ISarifResponse> | null,
) => {
  if (report === null) {
    return "Die Überprüfung der Protokolle TLS 1.1 und älter sowie SSL konnte nicht durchgeführt werden.";
  }
  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === TLSInspectionType.DeprecatedTLSDeactivated,
  );
  if (!inspection || inspection?.kind === "notApplicable") {
    return "Die Überprüfung der Protokolle TLS 1.1 und älter sowie SSL konnte nicht durchgeführt werden.";
  } else if (inspection.kind === "pass") {
    return "Die Protokolle TLS 1.1 und älter sowie SSL sind deaktiviert.";
  } else {
    return "Die Protokolle TLS 1.1 und älter sowie SSL sind nicht deaktiviert.";
  }
};
