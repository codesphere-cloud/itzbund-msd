import { TLSInspectionType } from "../scanner/scans";
import { DetailedTarget, ISarifResponse } from "../types";
import { DTO } from "../utils/server";

export const getTLSv1_3ReportMessage = (report: DTO<ISarifResponse> | null) => {
  if (report === null) {
    return "Die Überprüfung des TLS 1.3 Protokolls konnte nicht durchgeführt werden.";
  }
  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === TLSInspectionType.TLSv1_3,
  );

  if (!inspection || inspection?.kind === "notApplicable") {
    return `Die Überprüfung des TLS 1.3 Protokolls konnte nicht durchgeführt werden.`;
  } else if (inspection.kind === "pass") {
    return `Der Server unterstützt das Protokoll TLS 1.3.`;
  } else {
    return `Der Server unterstützt das Protokoll TLS 1.3 nicht.`;
  }
};
