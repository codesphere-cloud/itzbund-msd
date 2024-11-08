import { NextResponse } from "next/server";
import { serverCtrl } from "../../../../services/serverCtrl";
import { serverSentEventsService } from "../../../../services/serverSentEventsService";

// disable static evaluation
export const dynamic = "force-dynamic";

export function GET() {
  // use the health route handler as initial setup as well.
  // otherwise we have to create a custom server for NextJS, which in turn would
  // make it much harder to use ESM only modules.
  serverCtrl.bootstrap();
  return NextResponse.json(
    {
      success: true,
      sseClients: serverSentEventsService.getConnectedClients(),
    },
    { status: 200 },
  );
}
