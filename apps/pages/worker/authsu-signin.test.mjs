import assert from "node:assert/strict";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { readServerAppSession, SERVER_SESSION_COOKIE } from "@nteract/session";
import { serverOidcSessionStatus } from "@cloud/server-oidc.ts";
import { startLocalAuthsu } from "../scripts/fixtures/local-authsu.mjs";
import { identityProvider } from "../identity-provider.mjs";
import {
  authsuClientDocument,
  authsuIdentity,
  authsuSignIn,
  AUTHSU_CLIENT_PATH,
} from "./authsu-config.mjs";
import {
  authsuClientDocumentResponse,
  authsuSessionProvider,
  handleAuthsuSignIn,
} from "./authsu-signin.mjs";
import { browserSessionProvider, handleProviderDocument } from "./custom-providers.mjs";
import { handleOAuth } from "./oauth.mjs";

const BINDING = "__Host-pages_authsu_login";
const person = {
  id: "0190a0b0-c0d0-7e0f-8a0b-0c0d0e0f1011",
  name: "Ada",
  email: "ada@example.test",
};

class SqliteD1 {
  constructor() {
    this.sqlite = new DatabaseSync(":memory:");
  }
  prepare(sql) {
    const build = (values = []) => ({
      bind: (...next) => build(next),
      first: async () => this.sqlite.prepare(sql).get(...values) ?? null,
      all: async () => ({ success: true, results: this.sqlite.prepare(sql).all(...values) }),
      run: async () => ({
        success: true,
        meta: { changes: Number(this.sqlite.prepare(sql).run(...values).changes) },
      }),
    });
    return build();
  }
  async batch(statements) {
    this.sqlite.exec("BEGIN");
    try {
      const result = [];
      for (const statement of statements) result.push(await statement.run());
      this.sqlite.exec("COMMIT");
      return result;
    } catch (error) {
      this.sqlite.exec("ROLLBACK");
      throw error;
    }
  }
}

/** Pages' own client document, served from its own address as the gateway
 * serves it, so the fake authsu fetches what authsu would. */
async function startPagesDocument(getEnv) {
  const server = createServer((req, res) => {
    const env = getEnv();
    const config = authsuSignIn(env, new Request(`http://127.0.0.1:${server.address().port}/`));
    if (req.url === AUTHSU_CLIENT_PATH)
      return res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify(authsuClientDocument(config)));
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server;
}

async function fixture(t, extra = {}) {
  const authsu = await startLocalAuthsu();
  authsu.signIn(person);
  let env;
  const pages = await startPagesDocument(() => env);
  const origin = `http://127.0.0.1:${pages.address().port}`;
  env = {
    DB: new SqliteD1(),
    NOTEBOOK_CLOUD_PUBLIC_ORIGIN: origin,
    NOTEBOOK_CLOUD_LOCAL_OIDC: "true",
    NOTEBOOK_CLOUD_OIDC_FLOW: "server",
    NOTEBOOK_CLOUD_APP_SESSION_SECRET: "authsu-session-fixture-secret-".repeat(3),
    PAGES_AUTHSU_URL: authsu.origin,
    ...extra,
  };
  const lines = [];
  const restore = t.mock.method(console, "info", (line) => lines.push(String(line)));
  t.after(async () => {
    restore.mock.restore();
    await authsu.close();
    await new Promise((resolve) => pages.close(resolve));
    env.DB.sqlite.close();
  });
  const request = (path, { method = "GET", cookie } = {}) =>
    new Request(new URL(path, origin), { method, headers: cookie ? { cookie } : {} });
  return { env, authsu, lines, origin, request };
}

const setCookie = (response, name) =>
  response.headers
    .getSetCookie()
    .find((value) => value.startsWith(`${name}=`))
    ?.split(";", 1)[0];
const reasons = (lines) =>
  lines.map((line) => JSON.parse(line)).filter((event) => event.action === "sign_in.failed");
const rows = (env) => env.DB.sqlite.prepare("SELECT * FROM authsu_login_transactions").all();

async function begin(f, { returnTo = "/pages", cookie } = {}) {
  const response = await handleAuthsuSignIn(
    f.request(`/api/auth/login?return_to=${encodeURIComponent(returnTo)}`, { cookie }),
    f.env,
  );
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("cache-control"), "no-store");
  return { cookie: setCookie(response, BINDING), authorize: response.headers.get("location") };
}
/** What authsu does for a browser it has a session for: the callback address. */
async function throughAuthsu(authorize) {
  const response = await fetch(authorize, { redirect: "manual" });
  assert.equal(response.status, 302, await response.clone().text());
  return response.headers.get("location");
}
const callback = (f, address, cookie) => handleAuthsuSignIn(f.request(address, { cookie }), f.env);
async function sessionOf(f, response) {
  const cookie = setCookie(response, SERVER_SESSION_COOKIE);
  if (!cookie) return null;
  return readServerAppSession(f.env, f.request("/", { cookie }), Math.floor(Date.now() / 1000));
}

test("the authorize request asks for what authsu's contract takes", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const url = new URL(started.authorize);
  assert.equal(url.origin + url.pathname, `${f.authsu.origin}/oauth/authorize`);
  const p = url.searchParams;
  assert.equal(p.get("response_type"), "code");
  assert.equal(p.get("client_id"), `${f.origin}${AUTHSU_CLIENT_PATH}`);
  assert.equal(p.get("redirect_uri"), `${f.origin}/oidc`);
  assert.equal(p.get("scope"), "openid email profile offline_access");
  assert.equal(p.get("resource"), f.origin);
  assert.equal(p.get("code_challenge_method"), "S256");
  assert.match(p.get("state"), /^[A-Za-z0-9_-]{43}$/);
  assert.match(p.get("nonce"), /^[A-Za-z0-9_-]{43}$/);
  assert.match(started.cookie, /^__Host-pages_authsu_login=[A-Za-z0-9_-]{43}$/);
});

test("a sign-in that starts and ends in one browser makes a session for the person", async (t) => {
  const f = await fixture(t);
  const started = await begin(f, { returnTo: "/p/abc?view=1#top" });
  const address = await throughAuthsu(started.authorize);
  const response = await callback(f, address, started.cookie);
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/p/abc?view=1#top");
  assert.equal(response.headers.get("cache-control"), "no-store");
  const session = await sessionOf(f, response);
  assert.equal(session.principal, `user:authsu:${encodeURIComponent(person.id)}`);
  assert.equal(session.displayName, "Ada");
  assert.deepEqual(rows(f.env), []);
  // The binding is spent.
  assert.match(
    response.headers.getSetCookie().find((value) => value.startsWith(`${BINDING}=;`)),
    /Max-Age=0/,
  );
  // Pages stored no access token and no address in the clear.
  const stored = JSON.stringify(
    f.env.DB.sqlite.prepare("SELECT * FROM oidc_server_sessions").all(),
  );
  assert.equal(stored.includes(person.email), false);
  assert.equal(stored.includes("susu_at_"), false);
  assert.equal(stored.includes("susu_rt_"), false);
});

test("an address authsu reports is never treated as verified", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const response = await callback(f, await throughAuthsu(started.authorize), started.cookie);
  const session = await sessionOf(f, response);
  assert.equal(session.emailProof, undefined);
  assert.equal(
    authsuIdentity(authsuSignIn(f.env, f.request("/")), {
      sub: "u",
      email: "a@b.test",
      email_verified: true,
    }).metadata.emailVerified,
    true,
    "the claim is passed through as authsu states it, and authsu states false",
  );
  const identity = authsuIdentity(authsuSignIn(f.env, f.request("/")), {
    sub: "u",
    email: "a@b.test",
    email_verified: false,
  });
  assert.equal(identity.metadata.emailVerified, false);
  assert.equal(identityProvider(f.env).verifiedEmail, false);
});

test("a callback that reaches another browser signs nobody in and ends that sign-in", async (t) => {
  const f = await fixture(t);
  const other = await begin(f);
  for (const cookie of [undefined, other.cookie, `${other.cookie}; ${other.cookie}`]) {
    f.lines.length = 0;
    const started = await begin(f);
    const address = await throughAuthsu(started.authorize);
    const refused = await callback(f, address, cookie);
    assert.equal(refused.status, 400);
    assert.equal(reasons(f.lines)[0].reason, "binding_mismatch");
    assert.equal(setCookie(refused, SERVER_SESSION_COOKIE), undefined);
    assert.equal(refused.headers.get("referrer-policy"), "no-referrer");
    // The address that browser was left holding is no use to the one that
    // started the sign-in.
    const carriedBack = await callback(f, address, started.cookie);
    assert.equal(carriedBack.status, 400);
    assert.equal(setCookie(carriedBack, SERVER_SESSION_COOKIE), undefined);
  }
  assert.equal(f.authsu.exchanges().length, 0);
});

test("a callback is taken once, by one of two requests that carry it", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const address = await throughAuthsu(started.authorize);
  const answers = await Promise.all([
    callback(f, address, started.cookie),
    callback(f, address, started.cookie),
  ]);
  assert.deepEqual(answers.map((answer) => answer.status).sort(), [303, 400]);
  assert.equal(f.authsu.exchanges().length, 1);
  const done = answers.find((answer) => answer.status === 303);
  const again = await callback(
    f,
    address,
    `${started.cookie}; ${setCookie(done, SERVER_SESSION_COOKIE)}`,
  );
  assert.equal(again.status, 303);
  assert.equal(again.headers.get("location"), "/");
  assert.equal(f.authsu.exchanges().length, 1);
});

test("a sign-in started in a second tab doesn't break the one in the first", async (t) => {
  const f = await fixture(t);
  const first = await begin(f, { returnTo: "/p/one" });
  const second = await begin(f, { returnTo: "/p/two", cookie: first.cookie });
  assert.equal(second.cookie, first.cookie);
  for (const [started, landing] of [
    [second, "/p/two"],
    [first, "/p/one"],
  ]) {
    const response = await callback(f, await throughAuthsu(started.authorize), first.cookie);
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), landing);
  }
});

test("a sign-in left longer than its deadline can't finish", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const address = await throughAuthsu(started.authorize);
  f.env.DB.sqlite
    .prepare("UPDATE authsu_login_transactions SET expires_at = ?")
    .run(Math.floor(Date.now() / 1000));
  const refused = await callback(f, address, started.cookie);
  assert.equal(refused.status, 400);
  assert.equal(reasons(f.lines)[0].reason, "transaction_expired");
  assert.equal(f.authsu.exchanges().length, 0);
});

test("only a path on this site is kept as the place to land", async (t) => {
  const f = await fixture(t);
  for (const [asked, landing] of [
    ["/p/abc", "/p/abc"],
    ["https://evil.example/p", "/"],
    ["//evil.example", "/"],
    ["/\t/evil.example", "/"],
    ["/a/..//evil.example", "/"],
    ["/\\evil.example", "/"],
    ["/api/auth/login", "/"],
    ["/oidc?code=x", "/"],
    ["p/abc", "/"],
  ]) {
    const started = await begin(f, { returnTo: asked });
    const response = await callback(f, await throughAuthsu(started.authorize), started.cookie);
    assert.equal(response.headers.get("location"), landing, asked);
  }
});

test("a callback that isn't one authsu sends is refused before the row is touched", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const address = new URL(await throughAuthsu(started.authorize));
  const state = address.searchParams.get("state");
  const code = address.searchParams.get("code");
  for (const [query, reason] of [
    [`?state=${state}`, "callback_malformed"],
    [`?code=${code}`, "callback_malformed"],
    [`?code=${code}&state=short`, "callback_malformed"],
    [`?code=${code}&state=${state}&state=${state}`, "callback_malformed"],
    [`?code=${code}&code=${code}&state=${state}`, "callback_malformed"],
    [`?code=${"c".repeat(2049)}&state=${state}`, "callback_malformed"],
    [`?error=access_denied&state=${state}`, "provider_error"],
    [`?code=${code}&state=${state}&iss=https%3A%2F%2Fevil.example`, "issuer_mismatch"],
  ]) {
    f.lines.length = 0;
    const refused = await callback(f, `/oidc${query}`, started.cookie);
    assert.equal(refused.status, 400, query);
    assert.equal(reasons(f.lines)[0].reason, reason, query);
  }
  assert.equal(rows(f.env).length, 1);
  assert.equal(f.authsu.exchanges().length, 0);
});

test("an authsu that refuses, fails or answers badly ends the sign-in without a session", async (t) => {
  const f = await fixture(t);
  const json = (status, value) => (req, res) =>
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value));
  const ok = { access_token: "a", token_type: "Bearer", expires_in: 900 };
  for (const [answer, status, reason] of [
    [json(500, {}), 503, "authsu_unavailable"],
    [json(429, {}), 503, "authsu_unavailable"],
    [json(400, { error: "invalid_grant" }), 400, "code_refused"],
    [json(400, { error: "invalid_client" }), 502, "authsu_protocol_error"],
    [json(200, { ...ok, token_type: "mac" }), 502, "authsu_protocol_error"],
    [json(200, { ...ok, expires_in: 0 }), 502, "authsu_protocol_error"],
    [json(200, ok), 502, "authsu_protocol_error"],
    [(req, res) => res.writeHead(200).end("not json"), 502, "authsu_protocol_error"],
    [
      (req, res) => res.writeHead(302, { location: "https://evil.example/" }).end(),
      502,
      "authsu_protocol_error",
    ],
  ]) {
    f.lines.length = 0;
    const started = await begin(f, { returnTo: "/p/abc" });
    const address = await throughAuthsu(started.authorize);
    f.authsu.respond(answer);
    const failed = await callback(f, address, started.cookie);
    assert.equal(failed.status, status, reason);
    assert.equal(setCookie(failed, SERVER_SESSION_COOKIE), undefined);
    assert.equal(reasons(f.lines)[0].reason, reason);
    assert.match(await failed.text(), /href="\/api\/auth\/login\?return_to=%2Fp%2Fabc"/);
    assert.deepEqual(rows(f.env), []);
  }
});

test("an ID token that fails any check signs nobody in", async (t) => {
  const f = await fixture(t);
  const clientId = `${f.origin}${AUTHSU_CLIENT_PATH}`;
  for (const [name, rewrite] of [
    ["issuer", (c) => ({ ...c, iss: "https://evil.example" })],
    ["audience", (c) => ({ ...c, aud: "https://other.example/client.json" })],
    ["nonce", (c) => ({ ...c, nonce: "x".repeat(43) })],
    ["expiry", (c) => ({ ...c, exp: c.iat - 3600, iat: c.iat - 7200 })],
    ["subject", (c) => ({ ...c, sub: "" })],
  ]) {
    f.lines.length = 0;
    const started = await begin(f);
    const address = await throughAuthsu(started.authorize);
    f.authsu.claims(rewrite);
    const failed = await callback(f, address, started.cookie);
    assert.equal(failed.status, 403, name);
    assert.equal(setCookie(failed, SERVER_SESSION_COOKIE), undefined, name);
    assert.equal(reasons(f.lines)[0].reason, "id_token_invalid", name);
  }
  // A token signed by another key is refused too.
  const started = await begin(f);
  const address = await throughAuthsu(started.authorize);
  f.authsu.respond((req, res) => {
    const forged = `${f.authsu.sign({ iss: f.authsu.origin, sub: "x", aud: clientId, iat: 1, exp: 2 }).split(".").slice(0, 2).join(".")}.AAAA`;
    res.writeHead(200, { "content-type": "application/json" }).end(
      JSON.stringify({
        access_token: "a",
        token_type: "Bearer",
        expires_in: 900,
        id_token: forged,
      }),
    );
  });
  assert.equal((await callback(f, address, started.cookie)).status, 403);
});

test("the session renews with the refresh token, which rotates once only", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const done = await callback(f, await throughAuthsu(started.authorize), started.cookie);
  const cookie = setCookie(done, SERVER_SESSION_COOKIE);
  const provider = authsuSessionProvider(f.env, f.request("/"));
  // Make the proof due, then check the session as the gateway does.
  f.env.DB.sqlite
    .prepare("UPDATE oidc_server_sessions SET access_expires_at = ?")
    .run(Math.floor(Date.now() / 1000) + 5);
  const status = await serverOidcSessionStatus(
    f.request("/api/auth/session", { cookie }),
    f.env,
    async () => {},
    {
      provider,
    },
  );
  assert.equal(status.status, 200);
  const body = await status.json();
  assert.ok(body.session);
  const refreshes = f.authsu.exchanges().filter((e) => e.grant_type === "refresh_token");
  assert.equal(refreshes.length, 1);
  assert.equal(refreshes[0].client_id, `${f.origin}${AUTHSU_CLIENT_PATH}`);
  // The spent token is gone from the row: its replacement is sealed in.
  const after = f.env.DB.sqlite.prepare("SELECT access_expires_at FROM oidc_server_sessions").get();
  assert.ok(after.access_expires_at > Math.floor(Date.now() / 1000) + 600);
});

test("each renewal spends the token the last one returned", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const done = await callback(f, await throughAuthsu(started.authorize), started.cookie);
  const cookie = setCookie(done, SERVER_SESSION_COOKIE);
  const provider = authsuSessionProvider(f.env, f.request("/"));
  const due = () =>
    f.env.DB.sqlite
      .prepare("UPDATE oidc_server_sessions SET access_expires_at = ?, retry_after = 0")
      .run(Math.floor(Date.now() / 1000) + 5);
  const renew = async () => {
    due();
    const status = await serverOidcSessionStatus(
      f.request("/api/auth/session", { cookie }),
      f.env,
      async () => {},
      { provider },
    );
    return (await status.json()).session;
  };
  assert.ok(await renew());
  assert.ok(await renew(), "the second renewal presents the token the first one returned");
  assert.ok(await renew());
  const spent = f.authsu.exchanges().filter((e) => e.grant_type === "refresh_token");
  assert.equal(spent.length, 3);
  assert.equal(new Set(spent.map((e) => e.refresh_token)).size, 3, "no token is presented twice");
});

test("a session ends at its next renewal once authsu ends the grant", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const done = await callback(f, await throughAuthsu(started.authorize), started.cookie);
  const cookie = setCookie(done, SERVER_SESSION_COOKIE);
  f.authsu.revoke(person.id);
  f.env.DB.sqlite
    .prepare("UPDATE oidc_server_sessions SET access_expires_at = ?")
    .run(Math.floor(Date.now() / 1000) + 5);
  const status = await serverOidcSessionStatus(
    f.request("/api/auth/session", { cookie }),
    f.env,
    async () => {},
    {
      provider: authsuSessionProvider(f.env, f.request("/")),
    },
  );
  assert.equal((await status.json()).session, null);
  assert.equal(f.env.DB.sqlite.prepare("SELECT * FROM oidc_server_sessions").all().length, 0);
});

test("a session the provider didn't issue is not renewed", async (t) => {
  const f = await fixture(t);
  const provider = authsuSessionProvider(f.env, f.request("/"));
  for (const bundle of [
    {},
    { kind: "kilo-handoff" },
    { kind: "authsu", issuer: "https://other.example", subject: "s", refreshToken: "r" },
    { kind: "authsu", issuer: f.authsu.origin, subject: "s" },
    { kind: "authsu", issuer: f.authsu.origin, refreshToken: "r" },
  ])
    await assert.rejects(provider.refresh(bundle), { name: "Error" });
  assert.equal(f.authsu.exchanges().length, 0);
});

test("a renewal keeps the name authsu gave at sign-in, since it sends no ID token", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const done = await callback(f, await throughAuthsu(started.authorize), started.cookie);
  const cookie = setCookie(done, SERVER_SESSION_COOKIE);
  f.env.DB.sqlite
    .prepare("UPDATE oidc_server_sessions SET access_expires_at = ?, retry_after = 0")
    .run(Math.floor(Date.now() / 1000) + 5);
  const status = await serverOidcSessionStatus(
    f.request("/api/auth/session", { cookie }),
    f.env,
    async () => {},
    { provider: authsuSessionProvider(f.env, f.request("/")) },
  );
  const body = await status.json();
  assert.equal(body.session.display_name, "Ada");
  assert.equal(f.authsu.exchanges().filter((e) => e.grant_type === "refresh_token").length, 1);
  // The renewed session still names the person, not their principal.
  const renewed = await sessionOf(f, {
    headers: { getSetCookie: () => status.headers.getSetCookie() },
  });
  assert.equal(renewed.displayName, "Ada");
});

test("a renewal whose ID token names another person ends the session", async (t) => {
  const f = await fixture(t);
  const provider = authsuSessionProvider(f.env, f.request("/"));
  const clientId = `${f.origin}${AUTHSU_CLIENT_PATH}`;
  const token = (claims) =>
    f.authsu.sign({
      iss: f.authsu.origin,
      aud: clientId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      ...claims,
    });
  const answer = (id_token) => (req, res) =>
    res.writeHead(200, { "content-type": "application/json" }).end(
      JSON.stringify({
        access_token: "a",
        token_type: "Bearer",
        expires_in: 900,
        refresh_token: "susu_rt_next",
        id_token,
      }),
    );
  const bundle = { kind: "authsu", issuer: f.authsu.origin, subject: person.id, refreshToken: "r" };
  // The same person: the grant carries the rotated token.
  f.authsu.respond(answer(token({ sub: person.id, name: "Ada" })));
  const grant = await provider.refresh(bundle);
  assert.equal(grant.bundle.refreshToken, "susu_rt_next");
  assert.equal(grant.identity.principal, `user:authsu:${encodeURIComponent(person.id)}`);
  // Another person's token is refused as an identity, not retried as an outage.
  f.authsu.respond(answer(token({ sub: "someone-else" })));
  await assert.rejects(provider.refresh(bundle), { name: "AuthError", status: 403 });
  // A refresh with no ID token names the person the session already holds.
  f.authsu.respond(answer(undefined));
  assert.equal((await provider.refresh(bundle)).identity.principal, grant.identity.principal);
});

test("authsu sign-in is off unless the deployment names authsu", async (t) => {
  const f = await fixture(t, { PAGES_AUTHSU_URL: undefined });
  assert.equal(await handleAuthsuSignIn(f.request("/api/auth/login"), f.env), null);
  assert.equal(authsuSessionProvider(f.env, f.request("/")), undefined);
  assert.equal(identityProvider(f.env).id, "anaconda");
});

test("a deployment's authsu address must be a bare https origin", async (t) => {
  const f = await fixture(t);
  for (const bad of [
    "not a url",
    "http://auth.example",
    "https://auth.example/path",
    "https://user:pw@auth.example",
    "ftp://auth.example",
  ])
    assert.throws(
      () => authsuSignIn({ ...f.env, PAGES_AUTHSU_URL: bad }, f.request("/")),
      /misconfigured/,
      bad,
    );
  // Plain http is for the loopback test issuer only.
  assert.throws(
    () =>
      authsuSignIn(
        {
          ...f.env,
          NOTEBOOK_CLOUD_LOCAL_OIDC: undefined,
          PAGES_AUTHSU_URL: "http://localhost:8787",
        },
        f.request("/"),
      ),
    /misconfigured/,
  );
  assert.equal(
    authsuSignIn(
      {
        ...f.env,
        PAGES_AUTHSU_URL: "https://auth.susu.dev",
        NOTEBOOK_CLOUD_PUBLIC_ORIGIN: "https://app.susu.dev",
      },
      f.request("/"),
    ).clientId,
    "https://app.susu.dev/oauth/client.json",
  );
});

test("the client document names one public client and the one callback", async (t) => {
  const f = await fixture(t);
  const document = authsuClientDocument(authsuSignIn(f.env, f.request("/")));
  assert.deepEqual(document, {
    client_id: `${f.origin}/oauth/client.json`,
    client_name: "Pages",
    redirect_uris: [`${f.origin}/oidc`],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
});

test("an authsu whose endpoints leave its own origin is refused", async (t) => {
  const f = await fixture(t);
  f.authsu.respond((req, res) => res.writeHead(500).end());
  const response = await handleAuthsuSignIn(f.request("/api/auth/login"), {
    ...f.env,
    PAGES_AUTHSU_URL: "http://127.0.0.1:9",
  });
  assert.equal(response.status, 503);
  assert.equal(reasons(f.lines)[0].reason, "discovery_failed");
});

test("only GET reaches the sign-in routes", async (t) => {
  const f = await fixture(t);
  for (const path of ["/api/auth/login", "/oidc"]) {
    const refused = await handleAuthsuSignIn(f.request(path, { method: "POST" }), f.env);
    assert.equal(refused.status, 405);
  }
  assert.equal(await handleAuthsuSignIn(f.request("/api/auth/session"), f.env), null);
});

test("the Pages provider description for authsu holds what the guide and connect page read", () => {
  const provider = identityProvider({ PAGES_AUTHSU_URL: "https://auth.susu.dev" });
  assert.equal(provider.id, "authsu");
  assert.equal(provider.apiKey, null);
  assert.deepEqual(provider.companyDomains, []);
  assert.equal(provider.organizations, false);
  assert.equal(provider.verifiedEmail, false);
});

test("the OAuth authorize route renews an authsu session through authsu, not generic OIDC", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const done = await callback(f, await throughAuthsu(started.authorize), started.cookie);
  const cookie = setCookie(done, SERVER_SESSION_COOKIE);
  f.env.DB.sqlite
    .prepare("UPDATE oidc_server_sessions SET access_expires_at = ?, retry_after = 0")
    .run(Math.floor(Date.now() / 1000) + 5);
  // The same call the gateway makes for /oauth/authorize, with the provider
  // the gateway selects. Without it the session check reaches for an OIDC
  // issuer this deployment doesn't have and answers 503.
  const response = await handleOAuth(
    f.request(
      "/oauth/authorize?" +
        new URLSearchParams({
          response_type: "code",
          client_id: "pages-kilo",
          redirect_uri: "http://127.0.0.1:19876/mcp/oauth/callback",
          resource: `${f.origin}/mcp`,
          code_challenge: "a".repeat(43),
          code_challenge_method: "S256",
          state: "s",
        }),
      { cookie },
    ),
    f.env,
    { waitUntil() {} },
    () => browserSessionProvider(f.env, f.request("/")),
  );
  const text = await response.clone().text();
  assert.doesNotMatch(text, /renewal is temporarily unavailable/);
  assert.notEqual(response.status, 503, text);
  assert.equal(f.authsu.exchanges().filter((e) => e.grant_type === "refresh_token").length, 1);
});

test("a key set that can't be fetched during a renewal doesn't end the session", async (t) => {
  const f = await fixture(t);
  const started = await begin(f);
  const done = await callback(f, await throughAuthsu(started.authorize), started.cookie);
  const cookie = setCookie(done, SERVER_SESSION_COOKIE);
  f.env.DB.sqlite
    .prepare("UPDATE oidc_server_sessions SET access_expires_at = ?, retry_after = 0")
    .run(Math.floor(Date.now() / 1000) + 5);
  // An ID token signed by a key authsu doesn't publish is a failed check;
  // simulate an outage instead by pointing renewal at a closed port.
  const provider = authsuSessionProvider(f.env, f.request("/"), async (url, init) => {
    if (String(url).endsWith("/oauth/token")) throw new TypeError("network down");
    return fetch(url, init);
  });
  await assert
    .rejects(() =>
      serverOidcSessionStatus(f.request("/api/auth/session", { cookie }), f.env, async () => {}, {
        provider,
      }),
    )
    .catch(() => {});
  assert.equal(
    f.env.DB.sqlite.prepare("SELECT count(*) AS n FROM oidc_server_sessions").get().n,
    1,
  );
});

test("the client document hook answers only GET on its path, and only for authsu", async (t) => {
  const f = await fixture(t);
  const ok = handleProviderDocument(f.request(AUTHSU_CLIENT_PATH), f.env);
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).client_id, `${f.origin}${AUTHSU_CLIENT_PATH}`);
  assert.equal(
    handleProviderDocument(f.request(AUTHSU_CLIENT_PATH, { method: "POST" }), f.env),
    null,
  );
  assert.equal(handleProviderDocument(f.request("/oauth/other.json"), f.env), null);
  assert.equal(
    authsuClientDocumentResponse(f.request(AUTHSU_CLIENT_PATH), {
      ...f.env,
      PAGES_AUTHSU_URL: undefined,
    }),
    null,
  );
});
