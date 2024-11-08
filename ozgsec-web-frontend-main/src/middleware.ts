import { NextRequest, NextResponse } from "next/server";

import { NextRequestWithAuth, withAuth } from "next-auth/middleware";
import HttpError from "./errors/HttpError";
import { featureFlags } from "./feature-flags";

export default function middleware(request: NextRequest) {
  try {
    if (
      featureFlags.dashboardEnabled &&
      (request.nextUrl.pathname.startsWith("/dashboard") ||
        request.nextUrl.pathname.startsWith("/auth") ||
        request.nextUrl.pathname.startsWith("/datenschutz"))
    ) {
      return NextResponse.error();
    }
    if (
      request.nextUrl.pathname.startsWith("/dashboard") ||
      request.nextUrl.pathname.startsWith("/administration")
    ) {
      return withAuth(request as NextRequestWithAuth, {
        callbacks: {
          authorized(params) {
            if (!params.token) {
              return false;
            }
            return params.token?.error === undefined;
          },
        },
      });
    }
    return NextResponse.next();
  } catch (e) {
    if (e instanceof HttpError) {
      return e.toNextResponse();
    }
    throw e;
  }
}
