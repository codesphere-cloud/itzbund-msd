import {
  CheckResult,
  checkResult2BorderClassName,
  checkResult2Icon,
  kind2CheckResult,
} from "./view";

describe("view test suite", () => {
  it.each([
    ["pass" as const, CheckResult.Passed],
    ["fail" as const, CheckResult.Failed],
    [undefined, CheckResult.Unknown],
    ["notApplicable" as const, CheckResult.Unknown],
  ])(
    "should correctly transform a didPass value to a check result managed by the frontend",
    (param, expected) => {
      const result = kind2CheckResult(param);
      expect(result).toEqual(expected);
    },
  );

  it.each([
    [CheckResult.Passed, "dunkelgruen-80"],
    [CheckResult.Failed, "hellorange-100"],
    [CheckResult.Critical, "rot-100"],
    [CheckResult.Unknown, "dunkelgrau-100"],
  ])(
    "should transform a checkResult to the correct tailwind classname",
    (param, expected) => {
      const result = checkResult2BorderClassName(param);
      expect(result).toEqual(expected);
    },
  );

  it.each([
    [CheckResult.Passed, "circle-check"],
    [CheckResult.Failed, "circle-xmark"],
    [CheckResult.Critical, "circle-exclamation"],
    [CheckResult.Unknown, "circle-question"],
  ])(
    "should transform a checkResult to the correct icon",
    (param, expected) => {
      const result = checkResult2Icon(param);
      expect(result.iconName).toEqual(expected);
    },
  );
});
