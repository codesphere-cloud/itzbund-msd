import { NextRequest, NextResponse } from "next/server";
import BadRequestException from "../../../../../errors/BadRequestException";
import { serverSentEventsService } from "../../../../../services/serverSentEventsService";
import { getCurrentUserOrGuestUser } from "../../../../../utils/server";
import { authOptions } from "../../../../../nextAuthOptions";

export const GET = async (req: NextRequest) => {
  const connectionId = req.nextUrl.searchParams.get("connectionId");
  if (!connectionId) {
    throw new BadRequestException();
  }
  const user = await getCurrentUserOrGuestUser(authOptions);
  serverSentEventsService.heartbeat(user.id, connectionId);
  return NextResponse.json({ success: true });
};
