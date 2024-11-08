import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../../db/connection";
import ForbiddenException from "../../../../../errors/ForbiddenException";
import NotFoundException from "../../../../../errors/NotFoundException";
import { UnauthorizedException } from "../../../../../errors/UnauthorizedException";
import { authOptions } from "../../../../../nextAuthOptions";
import { keycloak } from "../../../../../services/keycloak";
import { isAdmin } from "../../../../../utils/common";
import { getJWTToken, getServerSession } from "../../../../../utils/server";
import { userService } from "../../../../../services/userService";
import { IUserPutDTO } from "../../../../../types";

interface Params {
  params: {
    userId: string;
  };
}

export async function PUT(req: NextRequest, { params }: Params) {
  const userId = params.userId as string;
  if (!userId) {
    throw new NotFoundException();
  }
  const [putRequest, token, session] = await Promise.all([
    req.json() as Promise<IUserPutDTO>,
    getJWTToken({ req }),
    getServerSession(authOptions),
  ]);

  if (!token) {
    throw new UnauthorizedException();
  }

  if (!isAdmin(session)) {
    throw new ForbiddenException();
  }

  const kcClient = keycloak.getKcAdminClient(token.accessToken);
  await kcClient.users.update(
    {
      id: userId,
      realm: keycloak.getRealmName(),
    },
    {
      username: putRequest.username,
    },
  );

  const user = await userService.updateUser(userId, putRequest, prisma);

  return NextResponse.json({
    ...user,
    username: putRequest.username,
  });
}

export async function DELETE(req: NextRequest, { params }: Params) {
  const userId = params.userId as string;
  if (!userId) {
    throw new NotFoundException();
  }
  const [token, session] = await Promise.all([
    getJWTToken({ req }),
    getServerSession(authOptions),
  ]);

  if (!token) {
    throw new UnauthorizedException();
  }

  if (!isAdmin(session)) {
    throw new ForbiddenException();
  }

  const kcClient = keycloak.getKcAdminClient(token.accessToken);
  await kcClient.users.del({ id: userId, realm: keycloak.getRealmName() });
  const user = await prisma.user.delete({
    where: { id: userId },
  });

  return NextResponse.json(user);
}
