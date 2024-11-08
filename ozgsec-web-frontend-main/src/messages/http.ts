import { HttpInspectionType } from "../scanner/scans";
import { ErrorCode, ISarifResponse } from "../types";
import { DTO } from "../utils/server";

export const getErrorMessage = (code: ErrorCode) => {
  switch (code) {
    case "could_not_resolve_hostname":
      return "Der DNS-Server konnte die Anfrage nicht beantworten. Es konnte keine IP-Adresse für die Domain oder das Weiterleitungsziel ermittelt werden.";
    case "could_not_parse_url":
      return "Bei der Eingabe scheint es sich nicht um eine gültige URL zu handeln.";
    default:
      return "Unbekannter Fehler.";
  }
};

export const getHttpMessage = (report: DTO<ISarifResponse> | null) => {
  if (report === null) {
    return "Die Überprüfung der HTTP Verbindung konnte nicht durchgeführt werden.";
  }
  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === HttpInspectionType.HTTP,
  );

  switch (inspection?.kind) {
    case "notApplicable":
      return "Die Verbindung konnte nicht überprüft werden.";
    case "fail":
      return `Die Verbindung konnte nicht hergestellt werden.`;
    case "pass":
      return `Eine Verbindung konnte hergestellt werden.`;
    default:
      return "Die Verbindung konnte nicht überprüft werden.";
  }
};
