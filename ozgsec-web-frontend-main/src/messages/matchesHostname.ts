import { CertificateInspectionType } from "../scanner/scans";
import { getSUTFromResponse } from "../services/sarifTransformer";
import { ISarifResponse } from "../types";
import { DTO } from "../utils/server";

export const getMatchesHostnameMessage = (
  report: DTO<ISarifResponse> | null,
) => {
  if (report === null) {
    return `Das Zertifikat des Servers konnte nicht überprüft werden.`;
  }

  const sut = getSUTFromResponse(report);
  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === CertificateInspectionType.MatchesHostname,
  );

  switch (inspection?.kind) {
    case "pass":
      return `Das Zertifikat des Servers ist für die Domain ${sut} ausgestellt worden.`;
    case "fail":
      return `Das Zertifikat des Servers ist nicht für die Domain ${sut} ausgestellt worden.`;
    default:
      return `Das Zertifikat des Servers konnte nicht überprüft werden.`;
  }
};
