import { User } from "next-auth";
import { JWT } from "next-auth/jwt";

declare module "next-auth" {
  interface User {
    id: string;
    collectionId?: number;
    name: string;
  }

  interface Profile {
    exp: number;
    iat: number;
    auth_time: number;
    jti: string;
    iss: string;
    aud: string;
    sub: string;
    typ: string;
    azp: string;
    session_state: string;
    at_hash: string;
    acr: string;
    sid: string;
    email_verified: boolean;
    realm_access: {
      roles: string[];
    };
    preferred_username: string;
  }

  interface Account {
    provider: string;
    type: string;
    providerAccountId: string;
    access_token: string;
    expires_at: number;
    refresh_token: string;
    token_type: string;
    id_token: string;
    session_state: string;
    scope: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    realmAccess: {
      roles: string[];
    };
    accessToken: string;
    expiresAt: number;
    refreshToken: string;
    idToken: string;
    username: string;
  }
}
