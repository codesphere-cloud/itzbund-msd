import { HSTSValidationError } from "../scanner/result-enums/header.typings";
import { HeaderInspectionType } from "../scanner/scans";
import { ISarifResponse } from "../types";
import { DTO } from "../utils/server";

export const getHSTSReportMessage = (report: DTO<ISarifResponse> | null) => {
  if (report === null) {
    return "Die Überprüfung des Strict-Transport-Security Headers konnte nicht durchgeführt werden.";
  }
  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === HeaderInspectionType.HSTS,
  );
  if (!inspection || inspection.kind === "notApplicable") {
    return "Die Überprüfung des Strict-Transport-Security Headers konnte nicht durchgeführt werden.";
  } else if (inspection.kind === "pass") {
    return "Strict-Transport-Security Header vorhanden und korrekt konfiguriert.";
  } else {
    switch (true) {
      case inspection.properties.errorIds.includes(
        HSTSValidationError.MissingHeader,
      ):
        return "Der Strict-Transport-Security Header ist nicht vorhanden.";
      case inspection.properties.errorIds.includes(
        HSTSValidationError.MissingMaxAge,
      ):
        return "Der Strict-Transport-Security Header ist vorhanden, enthält aber keinen max-age Parameter.";
      default:
        return "Strict-Transport-Security Header nicht vorhanden oder nicht korrekt konfiguriert.";
    }
  }
};
