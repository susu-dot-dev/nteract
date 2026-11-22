// Node-only loopback fake of the authsu routes Pages signs in through: OpenID
// discovery, the key set, the authorize endpoint and the token endpoint.
//
// It follows authsu's contract (docs/oauth_design.md in that repository), not
// a looser one: the client is a metadata document it fetches and whose
// callback it compares, PKCE S256 is required, a code is single use, the
// refresh token rotates once only, and an ID token is issued at the code
// exchange and never at a refresh. ID tokens are real RS256 JWTs signed with a
// key only the fake holds, so Pages verifies them against the published key
// set.
//
// An account is `{ id, name?, email? }`. `signIn(account)` sets who the browser
// is at authsu, or nobody with `null`. `claims(fn)` rewrites the claims of the
// next ID token, and `respond(fn)` replaces the next token answer.
import { createServer } from "node:http";
import { createHash, generateKeyPairSync, randomBytes, createSign } from "node:crypto";

const b64 = (value) => Buffer.from(value).toString("base64url");
const send = (res, status, value, headers = {}) =>
  res
    .writeHead(status, { "content-type": "application/json", ...headers })
    .end(JSON.stringify(value));

export async function startLocalAuthsu({ port = 0, now = Date.now, accessSeconds = 900 } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "fake-1", use: "sig", alg: "RS256" };
  const sign = (claims) => {
    const input = `${b64(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "fake-1" }))}.${b64(JSON.stringify(claims))}`;
    const signature = createSign("RSA-SHA256").update(input).sign(privateKey).toString("base64url");
    return `${input}.${signature}`;
  };
  const codes = new Map();
  const refreshTokens = new Map();
  const exchanges = [];
  const authorizations = [];
  let account = null;
  let origin = "";
  let rewriteClaims = null;
  let override = null;
  const revoked = new Set();

  const issue = (grant, { withIdToken }) => {
    const at = Math.floor(now() / 1000);
    const refresh = `susu_rt_${randomBytes(32).toString("base64url")}`;
    refreshTokens.set(refresh, grant);
    const claims = {
      iss: origin,
      sub: grant.account.id,
      aud: grant.clientId,
      iat: at,
      exp: at + 300,
      auth_time: at,
      ...(grant.nonce ? { nonce: grant.nonce } : {}),
      ...(grant.account.name ? { name: grant.account.name } : {}),
      ...(grant.account.email ? { email: grant.account.email, email_verified: false } : {}),
    };
    const rewritten = rewriteClaims ? rewriteClaims(claims) : claims;
    rewriteClaims = null;
    return {
      access_token: `susu_at_${randomBytes(32).toString("base64url")}`,
      token_type: "Bearer",
      expires_in: accessSeconds,
      refresh_token: refresh,
      scope: "openid profile",
      ...(withIdToken ? { id_token: sign(rewritten) } : {}),
    };
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration")
      return send(res, 200, {
        issuer: origin,
        authorization_endpoint: `${origin}/oauth/authorize`,
        token_endpoint: `${origin}/oauth/token`,
        jwks_uri: `${origin}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        id_token_signing_alg_values_supported: ["RS256"],
        subject_types_supported: ["public"],
      });
    if (req.method === "GET" && url.pathname === "/.well-known/jwks.json")
      return send(res, 200, { keys: [jwk] });
    if (req.method === "GET" && url.pathname === "/oauth/authorize") {
      const p = url.searchParams;
      authorizations.push(Object.fromEntries(p));
      if (!account) return send(res, 401, { error: "login_required" });
      // authsu reads the client's document and holds the request to what it
      // lists. The fake does the same, so a callback Pages never published is
      // refused here and not only in a test's assertion.
      let document;
      try {
        document = await (await fetch(p.get("client_id"))).json();
      } catch {
        return send(res, 400, { error: "invalid_client" });
      }
      if (
        document.client_id !== p.get("client_id") ||
        !document.redirect_uris?.includes(p.get("redirect_uri")) ||
        p.get("response_type") !== "code" ||
        p.get("code_challenge_method") !== "S256" ||
        !p.get("code_challenge") ||
        !p.get("state")
      )
        return send(res, 400, { error: "invalid_request" });
      const code = `susu_code_${randomBytes(24).toString("base64url")}`;
      codes.set(code, {
        account,
        clientId: p.get("client_id"),
        redirectUri: p.get("redirect_uri"),
        challenge: p.get("code_challenge"),
        nonce: p.get("nonce"),
        issuedAt: now(),
      });
      const back = new URL(p.get("redirect_uri"));
      back.searchParams.set("code", code);
      back.searchParams.set("state", p.get("state"));
      back.searchParams.set("iss", origin);
      return res.writeHead(302, { location: back.href }).end();
    }
    if (req.method === "POST" && url.pathname === "/oauth/token") {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      exchanges.push(Object.fromEntries(form));
      if (override) {
        const fn = override;
        override = null;
        return fn(req, res);
      }
      if (form.get("grant_type") === "authorization_code") {
        const grant = codes.get(form.get("code"));
        codes.delete(form.get("code"));
        const verifier = form.get("code_verifier") ?? "";
        const challenge = createHash("sha256").update(verifier).digest("base64url");
        if (
          !grant ||
          now() - grant.issuedAt > 60_000 ||
          grant.clientId !== form.get("client_id") ||
          grant.redirectUri !== form.get("redirect_uri") ||
          grant.challenge !== challenge
        )
          return send(res, 400, { error: "invalid_grant" });
        return send(res, 200, issue(grant, { withIdToken: true }));
      }
      if (form.get("grant_type") === "refresh_token") {
        const token = form.get("refresh_token");
        const grant = refreshTokens.get(token);
        // Once only, and no history: a token already spent is unknown.
        refreshTokens.delete(token);
        if (!grant || revoked.has(grant.account.id))
          return send(res, 400, { error: "invalid_grant" });
        return send(res, 200, issue(grant, { withIdToken: false }));
      }
      return send(res, 400, { error: "unsupported_grant_type" });
    }
    return send(res, 404, { error: "not_found" });
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  return {
    origin,
    /** Who the browser is at authsu, or nobody. */
    signIn(next) {
      account = next;
    },
    /** Ends every grant of an account, as revoking the Pages agent does. */
    revoke(id) {
      revoked.add(id);
    },
    /** Rewrites the claims of the next ID token. */
    claims(fn) {
      rewriteClaims = fn;
    },
    /** Replaces the next token answer with `fn(req, res)`. */
    respond(fn) {
      override = fn;
    },
    exchanges: () => exchanges.slice(),
    authorizations: () => authorizations.slice(),
    jwk,
    sign,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
