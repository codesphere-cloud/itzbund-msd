import { CertificateInspectionType } from "../scanner/scans";
import { ISarifResponse } from "../types";
import { DTO } from "../utils/server";

export const getValidCertificateMessage = (
  report: DTO<ISarifResponse> | null,
) => {
  if (report === null) {
    return `Das Zertifikat der Domain oder des Weiterleitungsziels konnte nicht überprüft werden.`;
  }
  if (
    report.runs[0].results.find(
      (r) => r.ruleId === CertificateInspectionType.ValidCertificate,
    )?.kind === "fail"
  ) {
    return `"Das Zertifikat der Domain oder des Weiterleitungsziels ist abgelaufen.`;
  }
  return `Das Zertifikat der Domain oder des Weiterleitungsziels ist valide.`;
};
