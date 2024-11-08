import { CheckResult } from "../utils/view";

export const legendMessages = (checkResult: CheckResult) => {
  switch (checkResult) {
    case CheckResult.Passed:
      return "Maßnahme umgesetzt";
    case CheckResult.Failed:
      return "Maßnahme nicht umgesetzt";
    case CheckResult.Critical:
      return "sofortiger Handlungsbedarf";
    default:
      return "Maßnahme konnte nicht überprüft werden";
  }
};
