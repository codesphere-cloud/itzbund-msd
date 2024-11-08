import { TextDecoder, TextEncoder } from "util";
import { HashedScanService } from "./hashedScanService";
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
        sut: "example.com",
        ipAddress: "198.168.172.1",
      },
    },
  ],
};

beforeEach(() => {
  Object.defineProperty(globalThis, "crypto", {
    value: {
      subtle: {
        digest: () => [1, 2, 3],
      },
    },
  });
});

describe("scanTargetRPC with disabled dashboard", () => {
  Object.assign(global, { TextEncoder, TextDecoder });
  const hashedURL = "010203";

  it("should check in the database if there is a scan already existing", async () => {
    const scanTarget = "https://example.com/";
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
    const sut = new HashedScanService({} as any, prismaMock as any);
    const [result] = await sut.scanTargetRPC("", scanTarget, {
      refreshCache: false,
      startTimeMS: Date.now(),
    });

    expect(result).toEqual(existing.details);
    expect(prismaMock.lastScanDetails.findFirst).toHaveBeenCalledWith({
      include: {
        target: true,
      },
      where: {
        uri: hashedURL,
        updatedAt: {
          gte: expect.anything(),
        },
      },
    });
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
    const sut = new HashedScanService(
      msgBrokerClientMock as any,
      prismaMock as any,
    );
    const [res] = await sut.scanTargetRPC("", "example.com", {
      refreshCache: false,
      startTimeMS: Date.now(),
    });

    expect(res).toEqual({
      ...scanReport,
      runs: [
        {
          ...scanReport.runs[0],
          properties: {
            ...scanReport.runs[0].properties,
            ipAddress: "198.168.0.0",
          },
        },
      ],
    });
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

    const sut = new HashedScanService(
      msgBrokerClientMock as any,
      prismaMock as any,
    );
    const [res] = await sut.scanTargetRPC("", "example.com", {
      refreshCache: false,
      startTimeMS: Date.now(),
    });

    expect(res).toEqual({
      ...scanReport,
      runs: [
        {
          ...scanReport.runs[0],
          properties: {
            ...scanReport.runs[0].properties,
            ipAddress: "198.168.0.0",
          },
        },
      ],
    });
  });
  it("should call reportService.handleNewScanReport with hashed values and shortened IP in result", async () => {
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
    await new HashedScanService(
      msgBrokerClientMock as any,
      prismaMock as any,
    ).scanTargetRPC("", "example.com", {
      refreshCache: false,
      startTimeMS: Date.now(),
    });

    expect(reportService.handleNewScanReport).toHaveBeenCalledWith(
      "",
      {
        runs: [
          {
            invocations: [{ exitCode: 0 }],
            properties: {
              ipAddress: "198.168.0.0",
              sut: "010203",
              target: "010203",
            },
            results: [{ kind: "pass", ruleId: "dnssec" }],
          },
        ],
      },
      expect.anything(),
      { refreshCache: false, startTimeMS: expect.any(Number) },
    );
  });
});
