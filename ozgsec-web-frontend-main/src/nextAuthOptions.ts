import { AuthOptions, CallbacksOptions } from "next-auth";
import { JWT } from "next-auth/jwt";
import CredentialsProvider from "next-auth/providers/credentials";
import KeycloakProvider from "next-auth/providers/keycloak";
import { prisma } from "./db/connection";
import { ISession } from "./types";

async function refreshAccessToken(token: JWT): Promise<JWT> {
  try {
    const response = await fetch(
      `${process.env.KEYCLOAK_ISSUER}/protocol/openid-connect/token`,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
        body: new URLSearchParams({
          client_id: process.env.KEYCLOAK_ID as string,
          grant_type: "refresh_token",
          refresh_token: token.refreshToken,
          client_secret: process.env.KEYCLOAK_SECRET as string,
        }),
      },
    );
    if (!response.ok) {
      throw response;
    }

    const refreshedTokens = await response.json();

    return {
      ...token,
      error: undefined,
      accessToken: refreshedTokens.access_token,
      expiresAt: Date.now() + refreshedTokens.expires_in * 1000,
      refreshToken: refreshedTokens.refresh_token ?? token.refreshToken, // Fall back to old refresh token
      idToken: refreshedTokens.id_token,
    };
  } catch (error) {
    return {
      ...token,
      error: "RefreshAccessTokenError",
    };
  }
}

const callbacks: CallbacksOptions = {
  signIn: () => true,
  async redirect({ url, baseUrl }) {
    // Allows relative callback URLs
    if (url.startsWith("/")) return `${baseUrl}${url}`;
    // Allows callback URLs on the same origin
    else if (new URL(url).origin === baseUrl) return url;
    return baseUrl;
  },
  async session(params) {
    return {
      ...params.session,
      user: {
        name: params.token.username,
        username: params.token.username,
        id: params.token.sub ?? (params.token.id as string),
        collectionId: params.token.collectionId as number,
      },
      realmAccess: params.token.realmAccess as ISession["realmAccess"],
      error: params.token.error as string,
    };
  },
  async jwt({ token, account, user, profile }): Promise<JWT> {
    if (user) {
      // check if guest user.
      // if so, the collectionId is defined on the user.
      if (user.collectionId) {
        return {
          user,
          accessToken: "",
          expiresAt: 0,
          username: user.name,
          refreshToken: "",
          idToken: "",
          realmAccess: {
            roles: [],
          },
        };
      }
    }

    if (profile) {
      token.realmAccess = profile.realm_access;
      token.username = profile.preferred_username;
    }
    if (account) {
      token.accessToken = account.access_token;
      token.expiresAt = account.expires_at * 1000;
      token.refreshToken = account.refresh_token;
      token.idToken = account.id_token;
    }

    if (token.expiresAt === undefined || Date.now() < token.expiresAt) {
      return token;
    }

    return refreshAccessToken(token);
  },
};

export const authOptions: AuthOptions = {
  pages: {
    signIn: "/auth/sign-in",
  },
  jwt: {
    maxAge: 30 * 60 * 60, // 1 day
  },
  providers: [
    CredentialsProvider({
      credentials: {},
      authorize: async (credentials: any) => {
        const shareLinkSecret = credentials?.shareLinkSecret;

        if (!shareLinkSecret) {
          return null;
        }
        // fetch the share link
        const link = await prisma.shareLink.findFirst({
          where: {
            secret: shareLinkSecret,
          },
          include: {
            collection: true,
          },
        });
        if (!link) {
          return null;
        }

        return {
          id: shareLinkSecret,
          collectionId: link.collection.id,
          name: link.collection.title,
        };
      },
    }),
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_ID as string,
      clientSecret: process.env.KEYCLOAK_SECRET as string,
      issuer: process.env.KEYCLOAK_ISSUER,
      profile(profile) {
        return {
          id: profile.sub,
          name: profile.preferred_username,
        };
      },
    }),
  ],
  callbacks,
};
