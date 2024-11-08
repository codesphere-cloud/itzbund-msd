import { NetworkInspectionType } from "../scanner/scans";
import { getSUTFromResponse } from "../services/sarifTransformer";
import { ISarifResponse } from "../types";
import { DTO } from "../utils/server";

const holderStr = (holder?: string) => {
  if (holder) {
    // prepend a space
    return ` ${holder}`;
  }
  return "";
};

export default function getRPKIReportMessage(
  report: DTO<ISarifResponse> | null,
) {
  if (report === null) {
    return `Der RPKI Status der Domain konnte nicht überprüft werden.`;
  }
  const inspection = report.runs[0].results.find(
    (r) => r.ruleId === NetworkInspectionType.RPKI,
  );
  const uri = getSUTFromResponse(report);

  if (!inspection || inspection.kind === "notApplicable") {
    return `Der RPKI Status der Domain ${uri} konnte nicht überprüft werden.`;
  } else if (inspection.kind === "pass") {
    let actualValue: {
      prefix: string;
      asn: number;
      holder: string;
    } = inspection.properties.actualValue as any;
    if (
      inspection.properties.actualValue instanceof Array &&
      inspection.properties.actualValue.length === 1
    ) {
      actualValue = inspection.properties.actualValue[0];
    } else if (
      inspection.properties.actualValue instanceof Array &&
      inspection.properties.actualValue.length > 1
    ) {
      return `Alle IP-Adressen Präfixe ${inspection.properties.actualValue
        .map((v) => v.prefix)
        .join(", ")} (AS: ${inspection.properties.actualValue
        .map((v) => `${v.asn}${holderStr(v.holder)}`)
        .join(", ")}) weisen valide Signaturen auf.`;
    }

    return `Das IP-Adressen Präfix ${actualValue.prefix} (AS: ${
      actualValue.asn
    }${holderStr(actualValue.holder)}) weist eine valide Signatur auf.`;
  } else {
    let actualValue: {
      prefix: string;
      asn: number;
      holder: string;
    } = inspection.properties.actualValue as any;
    if (
      inspection.properties.actualValue instanceof Array &&
      inspection.properties.actualValue.length === 1
    ) {
      actualValue = inspection.properties.actualValue[0];
    } else if (
      inspection.properties.actualValue instanceof Array &&
      inspection.properties.actualValue.length > 1
    ) {
      return `Mindestens eines der IP-Adressen Präfixe ${inspection.properties.actualValue
        .map((v) => v.prefix)
        .join(", ")} (AS: ${inspection.properties.actualValue
        .map((v) => `${v.asn}${holderStr(v.holder)}`)
        .join(", ")}) weist keine valide Signatur auf.`;
    }
    return `Das IP-Adressen Präfix ${actualValue.prefix} (AS: ${
      actualValue.asn
    }${holderStr(actualValue.holder)}) weist keine Signatur auf.`;
  }
}
