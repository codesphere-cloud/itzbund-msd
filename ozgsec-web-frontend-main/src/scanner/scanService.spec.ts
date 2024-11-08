import { ScanService } from "./scanService";
import { reportService } from "../services/reportService";

jest.mock("next-auth", () => ({}));
jest.mock("next-auth/jwt", () => ({}));
jest.mock("../app/api/auth/[...nextauth]/route", () => ({}));
jest.mock("../db/connection", () => ({
  prisma: {},
}));
jest.mock("../services/reportService", () => {
  return {
    reportService: {
      handleNewScanReport: jest.fn(),
    },
  };
});

const scanReport = {
  runs: [
    {
      invocations: [{ exitCode: 0 }],
      results: [
        {
          kind: "pass",
          ruleId: "dnssec",
        },
      ],
      properties: {
        target: "example.com",
        sut: "",
      },
    },
  ],
};

describe("ScanService test suite", () => {
  it("should check in the database if there is a scan already existing", async () => {
    const existing = {
      details: scanReport,
    };
    const prismaMock = {
      lastScanDetails: {
        findFirst: jest.fn().mockResolvedValue(existing), // there is a scan already
      },
    };

    // it would throw an error if there is no scan already since we are
    // trying to call a method on the empty object (MessageBrokerClient)
    const sut = new ScanService({} as any, prismaMock as any);
    const [result] = await sut.scanTargetRPC("", "example.com", {
      refreshCache: false,
      startTimeMS: Date.now(),
    });

    expect(result).toEqual(existing.details);
  });

  it("should return the scan report, even if there is an error during the database handling", async () => {
    const msgBrokerClientMock = {
      call: jest.fn().mockResolvedValue(scanReport),
    };

    const prismaMock = {
      scanReport: {
        findMany: jest.fn().mockResolvedValue([]),
        create: jest.fn().mockRejectedValue(new Error("error")),
      },
      lastScanDetails: {
        findFirst: jest.fn().mockResolvedValue(null), // there is no scan already
      },
      target: {
        upsert: jest.fn().mockResolvedValue({
          uri: "example.com",
        }),
      },
    };
    const sut = new ScanService(msgBrokerClientMock as any, prismaMock as any);
    const [res] = await sut.scanTargetRPC("", "example.com", {
      refreshCache: false,
      startTimeMS: Date.now(),
    });

    expect(res).toEqual(scanReport);
  });
  it("should return the new scan report if the scan was successful", async () => {
    const msgBrokerClientMock = {
      call: jest.fn().mockResolvedValue(scanReport),
    };

    const prismaMock = {
      scanReport: {
        findMany: jest.fn().mockResolvedValue([]),
        create: jest.fn(),
      },
      lastScanDetails: {
        findFirst: jest.fn().mockResolvedValue(null), // there is no scan already
      },
      target: {
        upsert: jest.fn().mockResolvedValue({
          uri: "example.com",
        }),
      },
    };

    const sut = new ScanService(msgBrokerClientMock as any, prismaMock as any);
    const [res] = await sut.scanTargetRPC("", "example.com", {
      refreshCache: false,
      startTimeMS: Date.now(),
    });

    expect(res).toEqual(scanReport);
  });

  it("should call handleNewScanReport of reportService", async () => {
    const msgBrokerClientMock = {
      call: jest.fn().mockResolvedValue(scanReport),
    };

    const prismaMock = {
      scanReport: {
        findMany: jest.fn().mockResolvedValue([]),
        create: jest.fn(),
      },
      lastScanDetails: {
        findFirst: jest.fn().mockResolvedValue(null), // there is no scan already
      },
      target: {
        upsert: jest.fn().mockResolvedValue({}),
      },
    };
    await new ScanService(
      msgBrokerClientMock as any,
      prismaMock as any,
    ).scanTargetRPC("", "example.com", {
      refreshCache: false,
      startTimeMS: Date.now(),
    });

    expect(reportService.handleNewScanReport).toHaveBeenCalled();
  });

  describe("after scan", () => {
    it("should issue a scan if the site is valid and there is no scan already existing", async () => {
      const msgBrokerClientMock = {
        call: jest.fn().mockResolvedValue(scanReport),
      };

      const prismaMock = {
        target: {
          upsert: jest.fn().mockResolvedValue({
            uri: "example.com",
          }),
        },
        scanReport: {
          findMany: jest.fn().mockResolvedValue([]),
          create: jest.fn(),
        },
        lastScanDetails: {
          findFirst: jest.fn().mockResolvedValue(null), // there is no scan already
        },
      };

      await new ScanService(
        msgBrokerClientMock as any,
        prismaMock as any,
      ).scanTargetRPC("", "example.com", {
        refreshCache: false,
        startTimeMS: Date.now(),
      });

      expect(msgBrokerClientMock.call).toHaveBeenCalled();
    });
    it("should issue a scan if the refresh query parameter is set to true", async () => {
      const msgBrokerClientMock = {
        call: jest.fn().mockResolvedValue(scanReport),
      };

      const prismaMock = {
        target: {
          upsert: jest.fn().mockResolvedValue({
            uri: "example.com",
          }),
        },
        scanReport: {
          findMany: jest.fn().mockResolvedValue([]),
          create: jest.fn(),
        },
        lastScanDetails: {
          findFirst: jest.fn().mockResolvedValue({}), // there is a scan already
        },
      };

      await new ScanService(
        msgBrokerClientMock as any,
        prismaMock as any,
      ).scanTargetRPC("", "example.com", {
        refreshCache: true,
        startTimeMS: Date.now(),
      });

      expect(msgBrokerClientMock.call).toHaveBeenCalled();
    });
  });
});
