import { config } from "../config";
import { scanService } from "../scanner/scanner.module";
import { reportService } from "./reportService";

jest.mock("next-auth", () => ({}));
jest.mock("next-auth/jwt", () => ({}));
const startAndEndTimeUtc = "2021-08-24T12:00:00.000Z";

describe("Report Service Test Suite", () => {
  it("should not create a new scan report if the reports did not change", async () => {
    const prismaMock = {
      scanReport: {
        findMany: jest.fn(() => [
          {
            dnsSec: true,
          },
        ]),
        create: jest.fn(),
      },
      target: {
        update: jest.fn(),
      },
      lastScanDetails: {
        findFirst: jest.fn(),
      },
    };
    jest.mock("../db/connection", () => ({
      prisma: prismaMock,
    }));

    await reportService.handleNewScanReport(
      "",
      {
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
              },
            ],
            properties: {
              target: "example.com",
            },
            results: [
              {
                ruleId: "dnsSec",
                kind: "pass",
              },
            ],
          },
        ],
      } as any,
      prismaMock as any,
      {
        refreshCache: false,
        startTimeMS: Date.now(),
      },
    );

    // it should not create a new scan report.
    expect(prismaMock.scanReport.create).not.toHaveBeenCalled();
    expect(prismaMock.target.update).toHaveBeenCalledWith({
      where: { uri: "example.com" },
      data: {
        queued: false,
        lastScan: 1629806400000,
        errorCount: 0,
        hostname: "example.com",
        lastScanDetails: {
          update: {
            updatedAt: new Date(startAndEndTimeUtc),
          },
        },
      },
    });
  });

  it("should not create a new scan report if the change could not be validated", async () => {
    const prismaMock = {
      scanReport: {
        findMany: jest.fn(() => [
          {
            dnsSec: true,
          },
        ]),
        create: jest.fn(),
      },
      target: {
        update: jest.fn(),
      },
      lastScanDetails: {
        findFirst: jest.fn(),
      },
    };
    jest.mock("../db/connection", () => ({
      prisma: prismaMock,
    }));

    config.socks5Proxy = "socks5://localhost:9050";
    const scanRPCValidation = jest
      .spyOn(scanService, "scanRPC")
      .mockResolvedValue({
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
              },
            ],
            properties: {
              target: "example.com",
            },
            results: [
              {
                ruleId: "dnsSec",
                kind: "pass",
              },
            ],
          },
        ],
      } as any);

    await reportService.handleNewScanReport(
      "",
      {
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
              },
            ],
            properties: {
              target: "example.com",
            },
            results: [
              {
                ruleId: "dnsSec",
                kind: "fail",
              },
            ],
          },
        ],
      } as any,
      prismaMock as any,
      {
        refreshCache: false,
        startTimeMS: Date.now(),
      },
    );
    // remove the config again
    config.socks5Proxy = undefined;

    expect(scanRPCValidation).toHaveBeenCalled();
    // it should not create a new scan report.
    expect(prismaMock.scanReport.create).not.toHaveBeenCalled();
    expect(prismaMock.target.update).toHaveBeenCalledWith({
      where: { uri: "example.com" },
      data: {
        queued: false,
        lastScan: 1629806400000,
        errorCount: 0,
        hostname: "example.com",
        lastScanDetails: {
          update: {
            updatedAt: new Date(startAndEndTimeUtc),
          },
        },
      },
    });
  });

  it.each([
    {
      event: "change",
      reports: [
        {
          dnsSec: false,
        },
      ],
    },
    {
      event: "not exist",
      reports: [],
    },
  ])(
    "should create a new scan report if the reports did %s (no validation)",
    async ({ reports }) => {
      const target = {
        uri: "example.com/test",
        queued: false,
        lastScan: 1629806400000,
        errorCount: 0,
        // make sure the hostname is set correctly.
        hostname: "example.com",
      };

      const prismaMock = {
        scanReport: {
          create: jest.fn(),
          findMany: jest.fn(() => reports),
        },
        target: {
          upsert: jest.fn(() => target),
        },
        lastScanDetails: {
          findFirst: jest.fn(),
        },
      };

      await reportService.handleNewScanReport(
        "",
        {
          runs: [
            {
              invocations: [
                {
                  endTimeUtc: startAndEndTimeUtc,
                  startTimeUtc: startAndEndTimeUtc,
                },
              ],
              properties: {
                target: "example.com/test",
              },
              results: [
                {
                  ruleId: "dnsSec",
                  kind: "pass",
                },
              ],
            },
          ],
        } as any,
        prismaMock as any,
        {
          refreshCache: false,
          startTimeMS: Date.now(),
        },
      );

      const lastScanDetails = {
        details: {
          runs: [
            {
              invocations: [
                {
                  endTimeUtc: startAndEndTimeUtc,
                  startTimeUtc: startAndEndTimeUtc,
                },
              ],
              properties: {
                target: "example.com/test",
              },
              results: [
                {
                  kind: "pass",
                  ruleId: "dnsSec",
                },
              ],
            },
          ],
        },
      };

      expect(prismaMock.scanReport.create).toHaveBeenCalled();
      expect(prismaMock.target.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { uri: "example.com/test" },
          create: {
            ...target,
            lastScanDetails: {
              create: lastScanDetails,
            },
          },
          update: {
            queued: false,
            lastScan: 1629806400000,
            errorCount: 0,
            hostname: "example.com",
            lastScanDetails: {
              upsert: {
                create: lastScanDetails,
                update: lastScanDetails,
              },
            },
          },
        }),
      );
    },
  );
  it("should validate a change in a scan report", async () => {
    const target = {
      uri: "example.com",
      queued: false,
      lastScan: 1629806400000,
      errorCount: 0,
      // make sure the hostname is set correctly.
      hostname: "example.com",
    };

    const prismaMock = {
      scanReport: {
        create: jest.fn(),
        findMany: jest.fn(() => [
          // a last report exists
          {
            dnsSec: false,
          },
        ]),
      },
      target: {
        upsert: jest.fn(() => target),
      },
      lastScanDetails: {
        findFirst: jest.fn(),
      },
    };

    // add a socks5 proxy inside the config
    config.socks5Proxy = "socks5://localhost:9050";
    const scanRPCValidation = jest
      .spyOn(scanService, "scanRPC")
      .mockResolvedValue({
        runs: [
          {
            invocations: [
              {
                endTimeUtc: "2021-08-24T14:00:00.000Z",
                startTimeUtc: "2021-08-24T14:00:00.000Z",
                exitCode: 0,
              },
            ],
            properties: {
              target: "example.com",
            },
            results: [
              {
                ruleId: "dnsSec",
                kind: "pass", // dnssec did indeed pass
              },
            ],
          },
        ],
      } as any);

    await reportService.handleNewScanReport(
      "",
      {
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
                exitCode: 0,
              },
            ],
            properties: {
              target: "example.com",
            },
            results: [
              {
                ruleId: "dnsSec",
                kind: "pass", // dnssec did indeed pass
              },
            ],
          },
        ],
      } as any,
      prismaMock as any,
      {
        refreshCache: false,
        startTimeMS: Date.now(),
      },
    );
    // remove the config again
    config.socks5Proxy = undefined;

    const lastScanDetails = {
      details: {
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
                exitCode: 0,
              },
            ],
            properties: {
              target: "example.com",
            },
            results: [
              {
                kind: "pass",
                ruleId: "dnsSec",
              },
            ],
          },
        ],
      },
    };
    expect(scanRPCValidation).toHaveBeenCalled();

    expect(prismaMock.scanReport.create).toHaveBeenCalled();
    expect(prismaMock.target.upsert).toHaveBeenCalledWith({
      where: { uri: "example.com" },
      create: {
        ...target,
        lastScan: 1629813600000, // timestamp of validation result
        lastScanDetails: {
          create: lastScanDetails,
        },
      },
      update: {
        queued: false,
        lastScan: 1629813600000, // timestamp of validation result
        errorCount: 0,
        hostname: "example.com",
        lastScanDetails: {
          upsert: {
            create: lastScanDetails,
            update: lastScanDetails,
          },
        },
      },
    });
  });
  it("should reduce null values by using the last scan report to fill in the gaps", async () => {
    const target = {
      uri: "example.com/test",
      queued: false,
      lastScan: 1629806400000,
      errorCount: 0,
      // make sure the hostname is set correctly.
      hostname: "example.com",
    };

    const prismaMock = {
      scanReport: {
        create: jest.fn(),
        findMany: jest.fn(() => [
          {
            dnsSec: true,
            responsibleDisclosure: true, // there is a value inside the last report
          },
        ]),
      },
      target: {
        upsert: jest.fn(() => target),
      },
      lastScanDetails: {
        findFirst: jest.fn(),
      },
    };

    await reportService.handleNewScanReport(
      "",
      {
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
                exitCode: 0,
              },
            ],
            properties: {
              target: "example.com/test",
            },
            results: [
              {
                kind: "notApplicable", // could not be checked
                ruleId: "responsibleDisclosure",
              },
              {
                kind: "fail",
                ruleId: "dnsSec",
              },
            ],
          },
        ],
      } as any,
      prismaMock as any,
      {
        refreshCache: false,
        startTimeMS: Date.now(),
      },
    );

    const replacedLastScanDetails = {
      details: {
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
                exitCode: 0,
              },
            ],
            properties: {
              target: "example.com/test",
            },
            results: [
              {
                kind: "pass", // replaced the value
                ruleId: "responsibleDisclosure",
                message: {
                  text: "",
                },
                properties: {
                  actualValue: {},
                  errorIds: [],
                  recommendationIds: [],
                }, // those are default values - they should be present when interpolating
              },
              {
                kind: "fail",
                ruleId: "dnsSec",
              },
            ],
          },
        ],
      },
    };

    expect(prismaMock.scanReport.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        dnsSec: false,
        responsibleDisclosure: true, // expect the value from the last report
      }),
    });

    expect(prismaMock.target.upsert).toHaveBeenCalledWith({
      where: { uri: "example.com/test" },
      create: {
        ...target,
        lastScanDetails: {
          create: replacedLastScanDetails, // expect replacements from last report
        },
      },
      update: {
        queued: false,
        lastScan: 1629806400000,
        errorCount: 0,
        hostname: "example.com",
        lastScanDetails: {
          upsert: {
            create: replacedLastScanDetails,
            update: replacedLastScanDetails,
          },
        },
      },
    });
  });

  it("should prefer the lastScanDetails over the last scan report to fill null values", async () => {
    const target = {
      uri: "example.com/test",
      queued: false,
      lastScan: 1629806400000,
      errorCount: 0,
      // make sure the hostname is set correctly.
      hostname: "example.com",
    };

    const prismaMock = {
      scanReport: {
        create: jest.fn(),
        findMany: jest.fn(() => [
          {
            dnsSec: true,
            responsibleDisclosure: true, // there is a value inside the last report
          },
        ]),
      },
      target: {
        upsert: jest.fn(() => target),
      },
      lastScanDetails: {
        findFirst: jest.fn(() => ({
          details: {
            runs: [
              {
                invocations: [
                  {
                    endTimeUtc: startAndEndTimeUtc,
                    startTimeUtc: startAndEndTimeUtc,
                    exitCode: 0,
                  },
                ],
                properties: {
                  target: "example.com/test",
                },
                results: [
                  {
                    kind: "pass", // could not be checked
                    ruleId: "responsibleDisclosure",
                    properties: {
                      actualValue: {
                        "security.txt": "whatever",
                      },
                    },
                  },
                  {
                    kind: "fail", // could not be checked
                    ruleId: "dnsSec",
                    actualValue: "whatever",
                  },
                ],
              },
            ],
          } as any,
        })),
      },
    };

    await reportService.handleNewScanReport(
      "",
      {
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
                exitCode: 0,
              },
            ],
            properties: {
              target: "example.com/test",
            },
            results: [
              {
                kind: "notApplicable", // could not be checked
                ruleId: "responsibleDisclosure",
              },
              {
                kind: "fail",
                ruleId: "dnsSec",
              },
            ],
          },
        ],
      } as any,
      prismaMock as any,
      {
        refreshCache: false,
        startTimeMS: Date.now(),
      },
    );

    const replacedLastScanDetails = {
      details: {
        runs: [
          {
            invocations: [
              {
                endTimeUtc: startAndEndTimeUtc,
                startTimeUtc: startAndEndTimeUtc,
                exitCode: 0,
              },
            ],
            properties: {
              target: "example.com/test",
            },
            results: [
              {
                kind: "pass", // could not be checked
                ruleId: "responsibleDisclosure",

                properties: {
                  actualValue: {
                    "security.txt": "whatever",
                  },
                },
              },
              {
                kind: "fail",
                ruleId: "dnsSec",
              },
            ],
          },
        ],
      },
    } as any;

    expect(prismaMock.scanReport.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        responsibleDisclosure: true, // expect the value from the last scan details
      }),
    });

    expect(prismaMock.target.upsert).toHaveBeenCalledWith({
      where: { uri: "example.com/test" },
      create: {
        ...target,
        lastScanDetails: {
          create: replacedLastScanDetails, // expect replacements from last report
        },
      },
      update: {
        queued: false,
        lastScan: 1629806400000,
        errorCount: 0,
        hostname: "example.com",
        lastScanDetails: {
          upsert: {
            create: replacedLastScanDetails,
            update: replacedLastScanDetails,
          },
        },
      },
    });
  });

  it("should not return that a scan report did change, if one of the values is null and the other one is undefined", () => {
    let actual = reportService.reportDidChange(
      { dnsSec: null } as any,
      { dnsSec: undefined } as any,
    );
    expect(actual).toBe(false);

    actual = reportService.reportDidChange(
      { dnsSec: undefined } as any,
      { dnsSec: null } as any,
    );

    expect(actual).toBe(false);
  });
});
