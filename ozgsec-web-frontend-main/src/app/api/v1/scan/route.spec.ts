import { NextResponse } from "next/server";
import { ISession } from "../../../../types";
import { getServerSession } from "../../../../utils/server";
import { staticSecrets } from "../../../../utils/staticSecrets";
import { GET } from "./route";

jest.mock("next-auth", () => ({}));
jest.mock("next-auth/jwt", () => ({}));
jest.mock("../../auth/[...nextauth]/route", () => ({}));
jest.mock("../../../../db/connection", () => ({
  prisma: {},
}));

const getServerSessionMock = getServerSession as jest.MockedFunction<
  typeof getServerSession
>;

jest.mock("../../../../utils/server", () => ({
  ...jest.requireActual("../../../../utils/server"),
  getServerSession: jest.fn(),
}));

NextResponse.json = jest.fn(
  (obj, responseInit?: ResponseInit) =>
    ({
      json: () => obj,
      status: responseInit?.status ?? 200,
    }) as any,
);

describe("Scan API Test Suite", () => {
  /*it("should return a 403 error if the secret is invalid and the user is not logged in", async () => {
    const res = await GET({
      nextUrl: {
        searchParams: new URLSearchParams({ s: "invalid" }),
      },
      headers: new Headers({}),
    } as any);
    expect(res.status).toEqual(401);
  });
  it("should not require a secret if the user is logged in", async () => {
    getServerSessionMock.mockResolvedValue({} as ISession);
    const res = await GET({
      nextUrl: {
        searchParams: new URLSearchParams({ s: "invalid" }),
      },
      headers: new Headers({}),
    } as any);
    // should be 400 since we did not provide any site
    expect(res.status).toEqual(400);
  }); */
  it("should return a 400 error if the site is not provided", async () => {
    getServerSessionMock.mockResolvedValue({} as ISession);
    const res = await GET({
      nextUrl: {
        searchParams: new URLSearchParams({ s: Object.keys(staticSecrets)[0] }),
      },
      headers: new Headers({}),
    } as any);
    expect(res.status).toEqual(400);
  });
  it("should return a 400 error if the site is not valid", async () => {
    getServerSessionMock.mockResolvedValue({} as ISession);
    const res = await GET({
      nextUrl: {
        searchParams: new URLSearchParams({
          site: "invalid",
          s: Object.keys(staticSecrets)[0],
        }),
      },
      headers: new Headers({}),
    } as any);
    expect(res.status).toEqual(400);
  });
});
