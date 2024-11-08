import { NextRequest, NextResponse } from "next/server";
import NotFoundException from "../../../errors/NotFoundException";
import BadRequestException from "../../../errors/BadRequestException";

export async function GET(request: NextRequest) {
  // get the referrer from the request headers
  const referrer = request.headers.get("referer");
  if (!referrer) {
    throw new BadRequestException("Referrer header is missing");
  }
  const loc = new URL(referrer);
  return NextResponse.redirect(
    `${
      process.env.KEYCLOAK_ISSUER
    }/protocol/openid-connect/auth?client_id=quicktest&redirect_uri=${encodeURIComponent(
      `${loc.protocol}//${loc.host}`,
    )}&response_type=code&scope=openid&kc_action=UPDATE_PASSWORD`,
  );
}
