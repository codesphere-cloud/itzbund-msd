import KcAdminClient from "@keycloak/keycloak-admin-client";

const getBaseUrl = () => {
  if (!process.env.KEYCLOAK_ISSUER) {
    throw new Error("KEYCLOAK_ISSUER is not defined");
  }
  const issuer = process.env.KEYCLOAK_ISSUER;
  const url = new URL(issuer);
  // build the base url from the issuer
  return `${url.protocol}//${url.hostname}:${url.port}`;
};

const getRealmName = () => {
  if (!process.env.KEYCLOAK_ISSUER) {
    throw new Error("KEYCLOAK_ISSUER is not defined");
  }
  const issuer = process.env.KEYCLOAK_ISSUER;
  return issuer.substring(issuer.lastIndexOf("/") + 1);
};

const getKcAdminClient = (accessToken: string) => {
  const kcAdminClient = new KcAdminClient({
    // the issuer contains the realm as well.
    baseUrl: getBaseUrl(),
    realmName: getRealmName(),
  });

  // set the access token
  kcAdminClient.setAccessToken(accessToken);
  return kcAdminClient;
};

export const keycloak = {
  getBaseUrl,
  getRealmName,
  getKcAdminClient,
};
