import { keycloak } from "../../../../services/keycloak";
import { getLogger } from "../../../../services/logger";
import { userService } from "../../../../services/userService";

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../db/connection";
import { UnauthorizedException } from "../../../../errors/UnauthorizedException";
import { ICreateUserDTO } from "../../../../types";
import { getJWTToken } from "../../../../utils/server";

const logger = getLogger(__filename);
export async function POST(req: NextRequest) {
  const [token, user] = await Promise.all([
    getJWTToken({ req }),
    req.json() as Promise<ICreateUserDTO>,
  ]);
  if (!token) {
    throw new UnauthorizedException();
  }

  const kcClient = keycloak.getKcAdminClient(token.accessToken);

  try {
    const password = `${Math.random()
      .toString(36)
      .substring(2, 15)
      .split("")
      .map((x) => (Math.random() > 0.5 ? x.toUpperCase() : x))
      .join("")}&`;
    const { id } = await kcClient.users.create({
      realm: keycloak.getRealmName(),
      firstName: "",
      lastName: "",
      username: user.username,
      emailVerified: true,
      enabled: true,
      requiredActions: ["UPDATE_PASSWORD"],
      credentials: [
        {
          type: "password",
          temporary: true,
          value: password,
        },
      ],
    });

    // create a new user inside our database as well.
    try {
      await userService.createUser(
        {
          ...user,
          _id: id,
        },
        prisma,
      );
      return NextResponse.json({
        success: true,
        password,
        user: {
          ...user,
          id,
        },
      });
    } catch (e) {
      logger.error({ error: e }, "Error creating user");
      // Rollback keycloak if this fails.
      await kcClient.users.del({ id, realm: keycloak.getRealmName() });
      return NextResponse.json({ success: false }, { status: 500 });
    }
  } catch (e: any) {
    logger.error({ error: e.message }, "Error creating user");
    return NextResponse.json({ success: false }, { status: 500 });
  }
}
