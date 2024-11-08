import { eachDay, eachWeek } from "./time";

describe("time.ts test suite", () => {
  it("should iterate over each week between start and end day", () => {
    const res = eachWeek(new Date("2020-01-01"), new Date("2020-01-31"));
    expect(res).toHaveLength(6);
    expect(new Date(res[0])).toEqual(new Date("2020-01-01"));
    expect(new Date(res[5])).toEqual(new Date("2020-01-31"));
  });
  it("should not include the start and end date, if they are the same", () => {
    const res = eachWeek(new Date("2020-01-01"), new Date("2020-01-01"));
    expect(res).toHaveLength(1);
  });

  it("should iterate over each day between start and end day", () => {
    const res = eachDay(new Date("2020-01-01"), new Date("2020-01-31"));
    expect(res).toHaveLength(31);
    expect(new Date(res[0])).toEqual(new Date("2020-01-01"));
    expect(new Date(res[30])).toEqual(new Date("2020-01-31"));
  });
});
