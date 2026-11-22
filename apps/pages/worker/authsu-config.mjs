/** A deployment's authsu sign-in settings and the Pages identity an authsu
 * account stands for. The browser sign-in (authsu-signin.mjs) reads them here.
 *
 * authsu is an OAuth 2.1 / OpenID Connect server. Pages is a first-party
 * public client of it: authorization code with PKCE, no client secret. The
 * client id is the URL of a client metadata document Pages serves itself
 * (`AUTHSU_CLIENT_PATH`), which authsu fetches to learn the callback. */

/** The principal namespace authsu accounts sign in under on this deployment. */
export const authsuPrincipalNamespace = (env) =>
  env?.PAGES_AUTHSU_PRINCIPAL_NAMESPACE?.trim() || "user:authsu";

/** Where Pages serves its client metadata document. authsu's client id is
 * this path on the Pages origin. */
export const AUTHSU_CLIENT_PATH = "/oauth/client.json";
/** Where authsu sends the browser back. It is the same `/oidc` callback every
 * Pages sign-in uses. */
export const AUTHSU_CALLBACK_PATH = "/oidc";
/** What authsu is asked for: who signed in, their name and address, and a
 * refresh token so a session can be renewed. */
export const AUTHSU_SCOPE = "openid email profile offline_access";

const LOOPBACK = ["localhost", "127.0.0.1", "[::1]"];

/** This deployment's authsu sign-in settings, or null when it doesn't use
 * authsu. `PAGES_AUTHSU_URL` turns it on and must be a bare `https:` origin;
 * a loopback `http:` origin is accepted only beside the local test issuer
 * flag. `PAGES_AUTHSU_RESOURCE` is the login resource authsu knows this
 * deployment by; it defaults to the Pages origin. A set but unusable value
 * throws, so a misconfigured deployment fails loudly and never falls back to
 * another sign-in. */
export function authsuSignIn(env, request) {
  const configured = env?.PAGES_AUTHSU_URL;
  if (!configured) return null;
  let issuer;
  try {
    issuer = new URL(String(configured));
  } catch {
    throw new Error("authsu sign-in is misconfigured");
  }
  const local = env.NOTEBOOK_CLOUD_LOCAL_OIDC === "true" && LOOPBACK.includes(issuer.hostname);
  if (
    (issuer.protocol !== "https:" && !(local && issuer.protocol === "http:")) ||
    String(configured).replace(/\/$/, "") !== issuer.origin ||
    issuer.username ||
    issuer.password
  )
    throw new Error("authsu sign-in is misconfigured");
  const origin = new URL(env.NOTEBOOK_CLOUD_PUBLIC_ORIGIN || request.url).origin;
  const resource = env.PAGES_AUTHSU_RESOURCE?.trim() || origin;
  return {
    issuer: issuer.origin,
    origin,
    clientId: `${origin}${AUTHSU_CLIENT_PATH}`,
    callback: `${origin}${AUTHSU_CALLBACK_PATH}`,
    resource,
    namespace: authsuPrincipalNamespace(env),
  };
}

/** The identity an authsu account stands for: its id and, when authsu sent
 * them, its name and address. The address is reported as authsu reports it.
 * authsu doesn't verify addresses, so it is never marked verified here, and
 * the session carries no email proof (app-session.ts). */
export function authsuIdentity(config, claims) {
  const principal = `${config.namespace}:${encodeURIComponent(claims.sub)}`;
  const name = typeof claims.name === "string" ? claims.name.trim() : "";
  const email = typeof claims.email === "string" ? claims.email.trim() : "";
  return {
    principal,
    operator: "browser",
    actorLabel: `${principal}/browser`,
    scope: "owner",
    metadata: {
      // The session label every server session carries (app-session.ts).
      provider: "oidc",
      transport: "host-session-cookie",
      principalNamespace: config.namespace,
      ...(name ? { displayName: name } : {}),
      ...(email ? { email, emailVerified: claims.email_verified === true } : {}),
    },
  };
}

/** The client metadata document authsu fetches for this deployment: the
 * client's name and the one callback it may use. A public client, so no
 * secret and token endpoint authentication `none`. */
export function authsuClientDocument(config) {
  return {
    client_id: config.clientId,
    client_name: "Pages",
    redirect_uris: [config.callback],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
}
