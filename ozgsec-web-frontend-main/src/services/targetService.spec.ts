import { InspectionType } from "../scanner/scans";
import { ISarifScanErrorResponse } from "../types";
import { targetService } from "./targetService";

jest.mock("next-auth", () => ({}));
jest.mock("next-auth/jwt", () => ({}));

describe("Target Service Test Suite", () => {
  it("should upsert the target if handleNewTarget is called", async () => {
    const prismaMock = {
      target: {
        upsert: jest.fn(),
      },
    } as any;
    await targetService.handleNewTarget(
      {
        uri: "example.com/test",
      },
      prismaMock,
    );
    expect(prismaMock.target.upsert).toHaveBeenCalledWith({
      where: { uri: "example.com/test" },
      update: {},
      create: {
        uri: "example.com/test",
        lastScan: null,
        queued: false,
        hostname: "example.com",
      },
    });
  });
  it("should create a user target relation if a user is provided", async () => {
    const prismaMock = {
      target: {
        upsert: jest.fn(),
      },
      targetCollectionRelation: {
        createMany: jest.fn(),
      },
    } as any;
    await targetService.handleNewTarget(
      {
        uri: "example.com/test",
      },
      prismaMock,
      { id: "1234", defaultCollectionId: 4711 } as any,
    );
    expect(prismaMock.targetCollectionRelation.createMany).toHaveBeenCalledWith(
      {
        skipDuplicates: true,
        data: [
          {
            collectionId: 4711,
            uri: "example.com/test",
          },
        ],
      },
    );
  });
  it("should delete the statistics of a collection if a target is added", async () => {
    const prismaMock = {
      target: {
        upsert: jest.fn(),
      },
      targetCollectionRelation: {
        createMany: jest.fn(),
      },
      stat: {
        deleteMany: jest.fn(),
      },
    } as any;
    await targetService.handleNewTarget(
      {
        uri: "example.com/test",
      },
      prismaMock,
      { id: "1234", defaultCollectionId: 4711 } as any,
    );
    // wait for the next tick
    await new Promise(process.nextTick);
    expect(prismaMock.stat.deleteMany).toHaveBeenCalled();
  });

  it("should create a target even if the scan failed", async () => {
    const prismaMock = {
      target: {
        upsert: jest.fn(),
      },
    } as any;

    const resp: ISarifScanErrorResponse = {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "OZGSEC",
              rules: [],
              properties: {
                scannerIp: "",
              },
            },
          },
          results: [],
          invocations: [
            {
              exitCode: 1,
              executionSuccessful: false,
              startTimeUtc: new Date().toISOString(),
              endTimeUtc: new Date().toISOString(),
            },
          ],
          properties: {
            target: "example.com/test",
            sut: "",
            ipAddress: "",
          },
        },
      ],
    };

    await targetService.handleTargetScanError(resp, prismaMock);
    expect(prismaMock.target.upsert).toHaveBeenCalledWith({
      where: {
        uri: "example.com/test",
      },
      update: {
        lastScan: expect.any(Number),
        queued: false,
        errorCount: {
          increment: 1,
        },
      },
      create: {
        errorCount: 1,
        uri: "example.com/test",
        lastScan: expect.any(Number),
        hostname: "example.com",
      },
    });
  });
  it.each([
    {
      actual: { [Math.random().toString().substring(2)]: "DROP TABLE" }, // any other value should default to uri.
      expected: "",
    },
    {
      actual: { responsibleDisclosure: "1", dnsSec: "-1", tlsv1_3: "0" },
      expected:
        '"responsibleDisclosure" = true AND "dnsSec" = false AND "tlsv1_3" IS NULL AND',
    },
    {
      actual: {
        responsibleDisclosure: "DROP TABLE", // should remove any values inside query params
        dnsSec: "-1",
        tlsv1_3: "0",
      },
      expected: '"dnsSec" = false AND "tlsv1_3" IS NULL AND',
    },
  ])(
    "should not be possible to inject arbitrary data to the sql statement when fetching the targets with their latest network results: %s",
    async ({ actual, expected }) => {
      const prismaMock = {
        target: {
          findMany: jest.fn(),
          count: jest.fn(),
        },
        $queryRawUnsafe: jest.fn(() => []),
      } as any;

      await targetService.getUserTargetsWithLatestTestResult(
        { id: "abc", defaultCollectionId: 0, featureFlags: {} },
        {
          sortDirection: "1",
          page: 0,
          pageSize: 10,
          ...(actual as { [key in InspectionType]?: "0" | "1" | "-1" }),
        },
        prismaMock,
      );

      const query = prismaMock.$queryRawUnsafe.mock.calls[0][0];
      const expectedQuery = `
      SELECT count(*) OVER() AS "totalCount", t.*, lsd.details as details from targets t
      LEFT JOIN scan_reports sr on t.uri = sr.uri
      LEFT JOIN last_scan_details lsd on t.uri = lsd.uri
      WHERE ${expected} NOT EXISTS(
          SELECT 1 from scan_reports sr2 where sr.uri = sr2.uri AND sr."createdAt" < sr2."createdAt"
        )
        AND EXISTS( SELECT 1 from target_collections tc where tc.uri = t.uri AND tc."collectionId" = $1 )
        ORDER BY ARRAY( SELECT ord || val FROM unnest(string_to_array(t.hostname, '.')) WITH ORDINALITY AS u(val, ord) ORDER BY ord ASC ) ASC
        LIMIT $2
        OFFSET $3;
`;
      expect(
        query
          .split("\n")
          .filter((s: string) => s.length > 0)
          .map((s: string) => s.trim())
          .join(" ")
          .replace(/\s+/g, " "),
      ).toEqual(
        expectedQuery
          .split("\n")
          .filter((s: string) => s.length > 0)
          .map((s) => s.trim())
          .join(" ")
          .replace(/\s+/g, " "),
      );
    },
  );
  it.each([
    {
      sort: Math.random().toString().substring(2), // any other value should default to uri.
      expected:
        "ARRAY( SELECT ord || val FROM unnest(string_to_array(t.hostname, '.')) WITH ORDINALITY AS u(val, ord) ORDER BY ord ASC )",
    },
    {
      sort: undefined,
      expected:
        "ARRAY( SELECT ord || val FROM unnest(string_to_array(t.hostname, '.')) WITH ORDINALITY AS u(val, ord) ORDER BY ord ASC )",
    },
  ])(
    "should not be possible to inject arbitrary data to the sql statement when fetching the targets with their latest network results: %s",
    async ({ sort, expected }) => {
      const prismaMock = {
        target: {
          findMany: jest.fn(),
          count: jest.fn(),
        },
        $queryRawUnsafe: jest.fn(() => []),
      } as any;

      await targetService.getUserTargetsWithLatestTestResult(
        { id: "abc", defaultCollectionId: 0, featureFlags: {} },
        {
          sortDirection: "1",
          page: 0,
          pageSize: 10,
        },
        prismaMock,
      );

      const query = prismaMock.$queryRawUnsafe.mock.calls[0][0];
      const expectedQuery = `
      SELECT count(*) OVER() AS "totalCount", t.*, lsd.details as details from targets t
      LEFT JOIN scan_reports sr on t.uri = sr.uri
      LEFT JOIN last_scan_details lsd on t.uri = lsd.uri
      WHERE NOT EXISTS(
          SELECT 1 from scan_reports sr2 where sr.uri = sr2.uri AND sr."createdAt" < sr2."createdAt"
        )
        AND EXISTS( SELECT 1 from target_collections tc where tc.uri = t.uri AND tc."collectionId" = $1 )
        ORDER BY ${expected} ASC
        LIMIT $2
        OFFSET $3;
`;
      expect(
        query
          .split("\n")
          .filter((s: string) => s.length > 0)
          .map((s: string) => s.trim())
          .join(" ")
          .replace(/\s+/g, " "),
      ).toEqual(
        expectedQuery
          .split("\n")
          .filter((s: string) => s.length > 0)
          .map((s) => s.trim())
          .join(" ")
          .replace(/\s+/g, " "),
      );
    },
  );

  it("should mark the targets as queued after retrieving them from the database for scanning", async () => {
    const targets = [
      {
        uri: "example.com/test",
      },
      {
        uri: "example.com/test2",
      },
    ];
    const prismaMock = {
      $queryRaw: jest.fn(() => targets),
      target: {
        findMany: jest.fn(() => targets),
        updateMany: jest.fn(),
      },
    } as any;

    await targetService.getTargets2Scan(prismaMock);
    expect(prismaMock.target.updateMany).toHaveBeenCalledWith({
      where: {
        uri: {
          in: ["example.com/test", "example.com/test2"],
        },
      },
      data: {
        queued: true,
      },
    });
    expect(prismaMock.target.updateMany).toHaveBeenCalledWith({
      where: {
        uri: {
          in: ["example.com/test", "example.com/test2"],
        },
      },
      data: {
        queued: true,
      },
    });
  });
});
