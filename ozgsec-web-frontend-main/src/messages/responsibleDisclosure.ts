import { ResponsibleDisclosureValidationError } from "../scanner/result-enums/organizational.typings";
import { OrganizationalInspectionType } from "../scanner/scans";
import { getSUTFromResponse } from "../services/sarifTransformer";
import { ISarifResponse } from "../types";
import { getUnicodeHostnameFromUri } from "../utils/common";
import { DTO } from "../utils/server";

export const getResponsibleDisclosureReportMessage = (
  report: DTO<ISarifResponse> | null,
) => {
  if (report === null) {
    return `Die Datei /.well-known/security.txt konnte nicht überprüft werden.`;
  }

  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === OrganizationalInspectionType.ResponsibleDisclosure,
  );

  const uri = getUnicodeHostnameFromUri(`http://${getSUTFromResponse(report)}`);
  if (!inspection || inspection.kind === "notApplicable") {
    return `Die Datei ${uri}/.well-known/security.txt konnte nicht überprüft werden.`;
  } else if (inspection.kind === "pass") {
    return `Die Datei ${uri}/.well-known/security.txt ist vorhanden und enthält die nötigen Einträge.`;
  } else {
    switch (true) {
      case inspection.properties.errorIds.includes(
        ResponsibleDisclosureValidationError.MissingContactField,
      ):
        return `Die Datei ${uri}/.well-known/security.txt ist vorhanden, enthält aber keinen Kontakt.`;
      case inspection.properties.errorIds.includes(
        ResponsibleDisclosureValidationError.InvalidExpiresField,
      ) ||
        inspection.properties.errorIds.includes(
          ResponsibleDisclosureValidationError.MissingExpiresField,
        ):
        return `Die Datei ${uri}/.well-known/security.txt ist vorhanden, enthält aber keinen gültigen Expires Eintrag.`;
      case inspection.properties.errorIds.includes(
        ResponsibleDisclosureValidationError.Expired,
      ):
        return `Die Datei ${uri}/.well-known/security.txt ist vorhanden, aber abgelaufen.`;
      case inspection.properties.errorIds.includes(
        ResponsibleDisclosureValidationError.MissingResponsibleDisclosure,
      ):
        const status = inspection.properties.actualValue.statusCode;
        if (status !== undefined && status !== -1) {
          return `Die Datei ${uri}/.well-known/security.txt ist nicht vorhanden. (Status: ${status})`;
        } else {
          return `Die Datei ${uri}/.well-known/security.txt ist nicht vorhanden.`;
        }
      // this check should always be AFTER the missing responsible disclosure check
      case inspection.properties.errorIds.includes(
        ResponsibleDisclosureValidationError.WrongMimeType,
      ):
        return `Die Datei ${uri}/.well-known/security.txt ist vorhanden, besitzt aber nicht den korrekten Content-Type: text/plain Header.`;
    }
  }
};
