/** Browser sign-in with an authsu account: OAuth 2.1 authorization code with
 * PKCE, Pages as a first-party public client.
 *
 * `GET /api/auth/login` stores a one-time transaction (the PKCE verifier, the
 * nonce and where the person was going) under a new `state`, sets an HttpOnly
 * cookie that binds the sign-in to this browser, and sends the browser to
 * authsu's authorize endpoint. authsu signs the person in with a passkey and
 * sends the browser back to `/oidc` with a code and the same `state`.
 *
 * The callback takes the stored row, trades the code for tokens at authsu's
 * token endpoint, checks the ID token's signature, issuer, audience, nonce
 * and subject against authsu's published keys, and starts a Pages session. A
 * session is created only if the callback carries the cookie the sign-in
 * started with, so a callback opened in another browser signs nobody in.
 *
 * Pages keeps authsu's refresh token sealed in the session row, and nothing
 * else of authsu's: the access token is not needed once the ID token proves
 * who signed in, so it is never stored. The session renews by exchanging the
 * refresh token; authsu rotates it on every exchange, so a renewal whose
 * answer was lost can't be repeated, and authsu ending the grant (a revoked
 * Pages agent or account) ends the session here at its next renewal.
 *
 * authsu reports an address but doesn't verify it, so the identity carries
 * the address without a verification proof (authsu-config.mjs). */
import {
  createServerSession,
  ServerSessionGrantRejected,
  ServerOidcIdentityRejected,
} from "@cloud/server-oidc.ts";
import { verifyOidcIdToken } from "@cloud/identity.ts";
import {
  cookieValue,
  openServerSecret,
  randomSecret,
  readServerAppSession,
  sealServerSecret,
  secretHash,
} from "@nteract/session";
import { browserSessionOptions } from "./browser-account.mjs";
import { recordOidcEvent } from "./auth-events.mjs";
import { migrateSchema } from "./catalog-index.mjs";
import { isolateSetup } from "./isolate-setup.mjs";
import {
  AUTHSU_CLIENT_PATH,
  AUTHSU_SCOPE,
  authsuClientDocument,
  authsuIdentity,
  authsuSignIn,
} from "./authsu-config.mjs";
import { html } from "./oauth.mjs";

const BINDING_COOKIE = "__Host-pages_authsu_login";
const LOGIN_PATH = "/api/auth/login";
const CALLBACK_PATH = "/oidc";
// How long a person has to get through authsu's sign-in page.
const LOGIN_SECONDS = 600;
const MAX_CODE_LENGTH = 2048;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 64 * 1024;
// The shape `randomSecret` gives a state and a binding.
const SECRET = /^[A-Za-z0-9_-]{43}$/;

const MIGRATIONS = Object.freeze([
  Object.freeze({
    version: 1,
    name: "login_transactions",
    statements: Object.freeze([
      // Normative in D1: the only copy of a sign-in in flight. It holds hashes
      // and one sealed blob, lives LOGIN_SECONDS, and is deleted when taken.
      `CREATE TABLE IF NOT EXISTS authsu_login_transactions (
        state_hash TEXT PRIMARY KEY,
        binding_hash TEXT NOT NULL,
        sealed TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )`,
    ]),
  }),
]);
const ready = isolateSetup((db) =>
  migrateSchema(db, { table: "authsu_login_schema", migrations: MIGRATIONS }),
);

/** authsu's endpoints could not be reached, or answered 429 or 5xx. Signing in
 * again may work. */
class AuthsuUnavailable extends Error {
  constructor(status) {
    super("authsu is temporarily unavailable");
    this.name = "AuthsuUnavailable";
    this.status = status;
  }
}
/** authsu answered with something this module doesn't accept. */
class AuthsuProtocolError extends Error {
  constructor(message = "authsu returned an invalid response") {
    super(message);
    this.name = "AuthsuProtocolError";
  }
}
/** authsu refused the code or the refresh token: the grant is over. */
class AuthsuGrantRefused extends Error {}

const noStore = (response) => {
  response.headers.set("Cache-Control", "no-store");
  return response;
};

/** A same-origin path to land on after sign-in, or `/`. */
function safeReturnTo(value, origin) {
  if (typeof value !== "string" || !value.startsWith("/") || /[\\\t\r\n]/.test(value)) return "/";
  let url;
  try {
    url = new URL(value, origin);
  } catch {
    return "/";
  }
  if (
    url.origin !== origin ||
    url.pathname.startsWith("//") ||
    url.pathname === CALLBACK_PATH ||
    url.pathname.startsWith("/api/auth/")
  )
    return "/";
  return url.pathname + url.search + url.hash;
}

function bindingOf(request) {
  const value = cookieValue(request, BINDING_COOKIE);
  return value && SECRET.test(value) ? value : null;
}

async function readLimited(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch {}
        throw new AuthsuProtocolError();
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof AuthsuProtocolError) throw error;
    throw new AuthsuUnavailable();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/** A request to authsu. Redirects are refused: a code, a verifier or a
 * refresh token must stay at the endpoint discovery named. */
async function authsuFetch(fetcher, url, init = {}) {
  let response;
  try {
    response = await fetcher(url, {
      ...init,
      headers: { Accept: "application/json", ...init.headers },
      redirect: "manual",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch {
    throw new AuthsuUnavailable();
  }
  if (response.status >= 300 && response.status < 400) {
    void response.body?.cancel().catch(() => {});
    throw new AuthsuProtocolError();
  }
  return response;
}

/** authsu's authorize and token endpoints, from its discovery document. Both
 * must be on the issuer's own origin. */
export async function authsuEndpoints(config, fetcher = fetch) {
  const response = await authsuFetch(fetcher, `${config.issuer}/.well-known/openid-configuration`);
  if (response.status === 429 || response.status >= 500)
    throw new AuthsuUnavailable(response.status);
  if (!response.ok) throw new AuthsuProtocolError();
  let document;
  try {
    document = JSON.parse(await readLimited(response));
  } catch (error) {
    if (error instanceof AuthsuUnavailable) throw error;
    throw new AuthsuProtocolError();
  }
  const endpoint = (name) => {
    let url;
    try {
      url = new URL(document?.[name]);
    } catch {
      throw new AuthsuProtocolError();
    }
    if (url.origin !== config.issuer || url.username || url.password || url.hash)
      throw new AuthsuProtocolError();
    return url.href;
  };
  if (document?.issuer !== config.issuer) throw new AuthsuProtocolError();
  return {
    authorization: endpoint("authorization_endpoint"),
    token: endpoint("token_endpoint"),
  };
}

/** The environment `verifyOidcIdToken` reads, naming authsu as the issuer and
 * this deployment's client as the audience. */
function idTokenEnvironment(env, config) {
  return {
    ...env,
    NOTEBOOK_CLOUD_OIDC_ISSUER: config.issuer,
    NOTEBOOK_CLOUD_OIDC_CLIENT_ID: config.clientId,
    NOTEBOOK_CLOUD_OIDC_AUDIENCE: config.clientId,
    NOTEBOOK_CLOUD_OIDC_JWKS_JSON: undefined,
  };
}

/** Posts a grant to authsu's token endpoint and returns its answer, or throws
 * what the failure means: `AuthsuGrantRefused` for `invalid_grant` (the code
 * or refresh token is over), `AuthsuUnavailable` for a failure signing in
 * again may clear, and `AuthsuProtocolError` for anything else. */
async function exchange(fetcher, endpoint, params) {
  const response = await authsuFetch(fetcher, endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params,
  });
  if (response.status === 429 || response.status >= 500)
    throw new AuthsuUnavailable(response.status);
  let value;
  try {
    value = JSON.parse(await readLimited(response));
  } catch (error) {
    if (error instanceof AuthsuUnavailable) throw error;
    throw new AuthsuProtocolError();
  }
  if (!response.ok) {
    if (value?.error === "invalid_grant") throw new AuthsuGrantRefused();
    throw new AuthsuProtocolError();
  }
  if (
    !value ||
    typeof value.access_token !== "string" ||
    String(value.token_type).toLowerCase() !== "bearer" ||
    !Number.isFinite(value.expires_in) ||
    value.expires_in <= 0 ||
    (value.refresh_token !== undefined && typeof value.refresh_token !== "string") ||
    (value.id_token !== undefined && typeof value.id_token !== "string")
  )
    throw new AuthsuProtocolError();
  return value;
}

/** `GET /api/auth/login`: stores the transaction under a new `state` and sends
 * the browser to authsu. A browser that already has a binding keeps it, so a
 * sign-in started in a second tab doesn't break the one in the first. */
async function beginLogin(request, env, config, fetcher) {
  const supplied = request.headers.get("origin");
  if (
    (supplied && supplied !== config.origin) ||
    request.headers.get("sec-fetch-site") === "cross-site"
  )
    return noStore(new Response("Start sign-in from this Pages site.", { status: 403 }));
  let endpoints;
  try {
    endpoints = await authsuEndpoints(config, fetcher);
  } catch (error) {
    return signInFailed(error instanceof AuthsuUnavailable ? 503 : 502, "discovery_failed");
  }
  const state = randomSecret();
  const binding = bindingOf(request) ?? randomSecret();
  const transaction = {
    verifier: randomSecret(),
    nonce: randomSecret(),
    returnTo: safeReturnTo(new URL(request.url).searchParams.get("return_to"), config.origin),
  };
  const stateHash = await secretHash(state);
  const now = Math.floor(Date.now() / 1000);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM authsu_login_transactions WHERE expires_at <= ?").bind(now),
    env.DB.prepare(
      "INSERT INTO authsu_login_transactions (state_hash, binding_hash, sealed, expires_at) VALUES (?, ?, ?, ?)",
    ).bind(
      stateHash,
      await secretHash(binding),
      await sealServerSecret(env, transaction, `authsu-login:${stateHash}`),
      now + LOGIN_SECONDS,
    ),
  ]);
  const url = new URL(endpoints.authorization);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.callback,
    scope: AUTHSU_SCOPE,
    resource: config.resource,
    state,
    nonce: transaction.nonce,
    code_challenge_method: "S256",
    code_challenge: await secretHash(transaction.verifier),
  }).toString();
  return noStore(
    new Response(null, {
      status: 302,
      headers: {
        Location: url.href,
        "Set-Cookie": `${BINDING_COOKIE}=${binding}; Path=/; Max-Age=${LOGIN_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
      },
    }),
  );
}

/** Tells the person a sign-in didn't finish and offers another. The audit log
 * gets the coded reason; the page says nothing about the account. */
function signInFailed(status, reason, returnTo = "/") {
  recordOidcEvent({
    type: "sign_in_failed",
    reason,
    phase: "authsu",
    kind: "authsu",
    outcome: "failure_page",
  });
  const retry = `${LOGIN_PATH}?return_to=${encodeURIComponent(returnTo)}`;
  const response = html(
    "Sign-in didn't finish",
    `<p>Pages couldn't finish signing you in.</p><p class="setup-actions"><a class="primary setup-action" href="${retry}">Try again</a></p>`,
    status,
  );
  // This page's address holds the code and state authsu sent.
  response.headers.set("Referrer-Policy", "no-referrer");
  return noStore(response);
}

/** The part of an ID token's claims a renewal keeps: what authsu said about the
 * person at sign-in, bounded so a sealed bundle stays small. */
const MAX_PROFILE_LENGTH = 512;
function profileOf(claims) {
  const keep = (value) =>
    typeof value === "string" && value.trim()
      ? value.trim().slice(0, MAX_PROFILE_LENGTH)
      : undefined;
  return {
    ...(keep(claims.name) && { name: keep(claims.name) }),
    ...(keep(claims.email) && {
      email: keep(claims.email),
      email_verified: claims.email_verified === true,
    }),
  };
}

/** What a verified ID token and a token answer prove: the identity, and the
 * grant to seal for renewal. */
async function grantFrom(env, config, tokens, { nonce, subject, expiresInCap }) {
  if (!tokens.id_token) throw new AuthsuProtocolError("missing ID token");
  const claims = await verifyOidcIdToken(idTokenEnvironment(env, config), tokens.id_token, {
    // A refresh may omit the nonce, but a nonce it returns must match.
    nonce,
    ...(subject ? { subject, allowMissingNonce: true } : {}),
  });
  const now = Math.floor(Date.now() / 1000);
  return {
    identity: authsuIdentity(config, claims),
    subject: claims.sub,
    profile: profileOf(claims),
    expiresAt: now + Math.min(tokens.expires_in, expiresInCap),
  };
}

// A session's proof is renewed this often. authsu's access token lives 15
// minutes; the session's own proof is bounded by it too.
const PROOF_CAP_SECONDS = 15 * 60;

/** `GET` on the callback: finishes the sign-in authsu sent back. */
async function completeLogin(request, env, config, fetcher) {
  const params = new URL(request.url).searchParams;
  const state = params.get("state");
  const code = params.get("code");
  if (params.has("error")) return signInFailed(400, "provider_error");
  if (
    !state ||
    !SECRET.test(state) ||
    !code ||
    code.length > MAX_CODE_LENGTH ||
    params.getAll("state").length !== 1 ||
    params.getAll("code").length !== 1
  )
    return signInFailed(400, "callback_malformed");
  // RFC 9207: a response that names another issuer is a mix-up attempt.
  if (params.has("iss") && params.get("iss") !== config.issuer)
    return signInFailed(400, "issuer_mismatch");
  const now = Math.floor(Date.now() / 1000);
  const stateHash = await secretHash(state);
  // One statement takes the row, whichever browser the callback reached, so a
  // state is good for one callback.
  const row = await env.DB.prepare(
    "DELETE FROM authsu_login_transactions WHERE state_hash = ? RETURNING binding_hash, sealed, expires_at",
  )
    .bind(stateHash)
    .first();
  if (!row) {
    // A repeated redirect or a restored tab delivers a callback whose sign-in
    // already finished. If this browser has a session, that sign-in worked.
    let session = null;
    try {
      session = await readServerAppSession(env, request, now);
    } catch {}
    if (session) return noStore(new Response(null, { status: 303, headers: { Location: "/" } }));
    return signInFailed(400, "transaction_missing");
  }
  if (row.expires_at <= now) return signInFailed(400, "transaction_expired");
  const binding = bindingOf(request);
  if (!binding || (await secretHash(binding)) !== row.binding_hash)
    return signInFailed(400, "binding_mismatch");
  let transaction;
  try {
    transaction = await openServerSecret(env, row.sealed, `authsu-login:${stateHash}`);
  } catch {
    return signInFailed(400, "transaction_unreadable");
  }
  const returnTo = safeReturnTo(transaction.returnTo, config.origin);
  let grant;
  let tokens;
  try {
    const endpoints = await authsuEndpoints(config, fetcher);
    tokens = await exchange(
      fetcher,
      endpoints.token,
      new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.clientId,
        code,
        redirect_uri: config.callback,
        code_verifier: transaction.verifier,
      }),
    );
    grant = await grantFrom(env, config, tokens, {
      nonce: transaction.nonce,
      expiresInCap: PROOF_CAP_SECONDS,
    });
  } catch (error) {
    if (error instanceof AuthsuUnavailable)
      return signInFailed(503, "authsu_unavailable", returnTo);
    if (error instanceof AuthsuGrantRefused) return signInFailed(400, "code_refused", returnTo);
    if (error instanceof AuthsuProtocolError)
      return signInFailed(502, "authsu_protocol_error", returnTo);
    // A bad ID token (signature, issuer, audience, nonce) is a refusal of the
    // sign-in, not an outage.
    if (error?.name === "AuthError" && error.status >= 500)
      return signInFailed(503, "authsu_unavailable", returnTo);
    if (error?.name === "AuthError") return signInFailed(403, "id_token_invalid", returnTo);
    throw error;
  }
  const sessionCookie = await createServerSession(
    request,
    env,
    {
      identity: grant.identity,
      expiresAt: grant.expiresAt,
      bundle: {
        kind: "authsu",
        issuer: config.issuer,
        subject: grant.subject,
        refreshToken: tokens.refresh_token,
        // authsu issues an ID token only at the code exchange, so a renewal has
        // no name or address of its own: it reuses these.
        profile: grant.profile,
      },
    },
    browserSessionOptions,
  );
  const done = noStore(
    new Response(null, {
      status: 303,
      headers: { Location: returnTo, "Set-Cookie": sessionCookie },
    }),
  );
  // The sign-in is over: the binding has nothing left to bind.
  done.headers.append(
    "Set-Cookie",
    `${BINDING_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
  );
  return done;
}

/** The provider `serverOidcSessionStatus` needs for a deployment that signs in
 * with authsu, or undefined when this one doesn't. It exchanges the sealed
 * refresh token, checks the ID token still names the same person, and returns
 * the next grant. authsu answering `invalid_grant` ends the session. */
export function authsuSessionProvider(env, request, fetcher = fetch) {
  const config = authsuSignIn(env, request);
  if (!config) return undefined;
  return {
    async refresh(bundle) {
      if (
        bundle?.kind !== "authsu" ||
        bundle.issuer !== config.issuer ||
        typeof bundle.refreshToken !== "string" ||
        typeof bundle.subject !== "string"
      )
        throw new ServerSessionGrantRejected();
      let tokens;
      try {
        const endpoints = await authsuEndpoints(config, fetcher);
        tokens = await exchange(
          fetcher,
          endpoints.token,
          new URLSearchParams({
            grant_type: "refresh_token",
            client_id: config.clientId,
            refresh_token: bundle.refreshToken,
          }),
        );
      } catch (error) {
        if (error instanceof AuthsuGrantRefused) throw new ServerSessionGrantRejected();
        throw error;
      }
      // authsu issues an ID token only at the code exchange, so a refresh
      // names the person by the one the session already holds. A new refresh
      // token replaces the old: authsu rotates it once only.
      const claims = tokens.id_token
        ? await verifyOidcIdToken(idTokenEnvironment(env, config), tokens.id_token, {
            subject: bundle.subject,
            allowMissingNonce: true,
          }).catch((error) => {
            // Only a token that fails a check names someone else. A key set
            // that couldn't be fetched (a 5xx AuthError, a timeout) is an
            // outage: the renewal is retried, and the session isn't ended.
            if (error?.name === "AuthError" && error.status < 500)
              throw new ServerOidcIdentityRejected();
            throw new AuthsuUnavailable();
          })
        : { ...profileOf(bundle.profile ?? {}), sub: bundle.subject };
      return {
        identity: authsuIdentity(config, claims),
        expiresAt: Math.floor(Date.now() / 1000) + Math.min(tokens.expires_in, PROOF_CAP_SECONDS),
        bundle: {
          ...bundle,
          refreshToken: tokens.refresh_token ?? bundle.refreshToken,
          // A renewal that does carry an ID token updates what is kept.
          ...(tokens.id_token && { profile: profileOf(claims) }),
        },
      };
    },
  };
}

/** authsu sign-in's routes. Returns null for any other path, and for every
 * path when this deployment doesn't use authsu, so the caller's own routes
 * answer. */
export async function handleAuthsuSignIn(request, env, fetcher = fetch) {
  const { pathname } = new URL(request.url);
  if (pathname !== LOGIN_PATH && pathname !== CALLBACK_PATH) return null;
  const config = authsuSignIn(env, request);
  if (!config) return null;
  if (request.method !== "GET") return noStore(new Response(null, { status: 405 }));
  await ready(env.DB);
  return pathname === LOGIN_PATH
    ? beginLogin(request, env, config, fetcher)
    : completeLogin(request, env, config, fetcher);
}

/** `GET /oauth/client.json`: the client metadata document authsu fetches to
 * learn this deployment's callback. Returns null for any other request, and
 * for every request when this deployment doesn't use authsu. */
export function authsuClientDocumentResponse(request, env) {
  if (request.method !== "GET" || new URL(request.url).pathname !== AUTHSU_CLIENT_PATH) return null;
  const config = authsuSignIn(env, request);
  if (!config) return null;
  return new Response(JSON.stringify(authsuClientDocument(config)), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
