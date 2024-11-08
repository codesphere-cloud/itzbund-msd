import {
  faCheckCircle,
  faCircleExclamation,
  faCircleQuestion,
  faCircleXmark,
} from "@fortawesome/free-solid-svg-icons";
import resolveConfig from "tailwindcss/resolveConfig";
import tinycolor from "tinycolor2";
import tailwindConfig from "../../tailwind.config";
import {
  AccessiblityInspectionType,
  DomainInspectionType,
  HeaderInspectionType,
  InspectionType,
  NetworkInspectionType,
  OrganizationalInspectionType,
  TLSInspectionType,
} from "../scanner/scans";
import { Falsey } from "lodash";

export enum CheckResult {
  Passed = "passed",
  Failed = "failed",
  Critical = "critical",
  Unknown = "unknown",
}

export const kind2CheckResult = (
  kind?: "notApplicable" | "fail" | "pass" | Falsey,
) => {
  switch (kind) {
    case "pass":
      return CheckResult.Passed;
    case "fail":
      return CheckResult.Failed;
    default:
      return CheckResult.Unknown;
  }
};

export const checkResult2BorderClassName = (checkResult: CheckResult) => {
  switch (checkResult) {
    case CheckResult.Passed:
      return "dunkelgruen-80";
    case CheckResult.Failed:
      return "hellorange-100";
    case CheckResult.Critical:
      return "rot-100";
    default:
      return "dunkelgrau-100";
  }
};

export const checkResult2TextClassName = (checkResult: CheckResult) => {
  switch (checkResult) {
    case CheckResult.Passed:
      return checkResult2BorderClassName(checkResult);
    case CheckResult.Failed:
      return checkResult2BorderClassName(checkResult);
    case CheckResult.Critical:
      return checkResult2BorderClassName(checkResult);
    default:
      return "dunkelgrau-100";
  }
};

export const checkResult2Icon = (checkResult: CheckResult) => {
  switch (checkResult) {
    case CheckResult.Passed:
      return faCheckCircle;
    case CheckResult.Failed:
      return faCircleXmark;
    case CheckResult.Critical:
      return faCircleExclamation;
    default:
      return faCircleQuestion;
  }
};

export const optimisticUpdate = <T>(
  currentState: T,
  setStateFn: (fn: (prev: T) => T) => void,
  transformer: (currentState: T) => T,
) => {
  const oldState = currentState;
  setStateFn(transformer);
  // return the reverting function
  return () => setStateFn(() => oldState);
};

export const displayInspections: Array<InspectionType> = [
  OrganizationalInspectionType.ResponsibleDisclosure,
  TLSInspectionType.TLSv1_3,
  TLSInspectionType.DeprecatedTLSDeactivated,
  HeaderInspectionType.HSTS,
  DomainInspectionType.DNSSec,
  NetworkInspectionType.RPKI,

  AccessiblityInspectionType.ProvidesEnglishWebsiteVersion,
];

const fullConfig = resolveConfig(tailwindConfig);
export const tailwindColors = (fullConfig.theme as any).colors;

export const secretToShareLink = (secret: string) => {
  return `/auth/sign-in?secret=${secret}`;
};

export const w = () => {
  if (typeof window !== "undefined") {
    return window;
  }
  return null;
};

export const adaptiveTextColorBasedOnContrast = (color: string) => {
  // check if the color is dark
  if (tinycolor(color).isDark()) {
    return "text-white";
  }
  return "text-deepblue-500";
};

export const localizeDefaultCollection = <
  T extends { id: number; title: string; color: string },
>(
  collection: T,
  defaultCollectionId: number,
  username: string,
): T => {
  if (collection.id === defaultCollectionId) {
    return {
      ...collection,
      color: tailwindColors.blau["100"],
      title: username,
    };
  }

  return collection;
};

const oneDay = 24 * 60 * 60 * 1000; // hours*minutes*seconds*milliseconds

export const diffDays = (firstDate: Date, secondDate: Date) =>
  Math.round(Math.abs((firstDate.getTime() - secondDate.getTime()) / oneDay));
