import { AccessiblityInspectionType } from "../scanner/scans";
import { ISarifResponse } from "../types";
import { DTO } from "../utils/server";

export const getProvidesEnglishWebsiteVersionMessage = (
  report: DTO<ISarifResponse> | null,
) => {
  if (report === null) {
    return "Die Überprüfung, ob die Website auch in englischer Sprache verfügbar ist, konnte nicht durchgeführt werden.";
  }
  const inspection = report.runs[0].results.find(
    (r) =>
      r.ruleId === AccessiblityInspectionType.ProvidesEnglishWebsiteVersion,
  );

  switch (inspection?.kind) {
    case "fail":
      return `Die Website ist nicht in englischer Sprache verfügbar. Konfidenz: ${Math.round(
        (1 - inspection.properties.actualValue.propability) * 100,
      )}%`;
    case "pass":
      return `Die Website ist in englischer Sprache verfügbar. Konfidenz: ${Math.round(
        inspection.properties.actualValue.propability * 100,
      )}%`;
    default:
      return "Die Überprüfung, ob die Website auch in englischer Sprache verfügbar ist, konnte nicht durchgeführt werden.";
  }
};
