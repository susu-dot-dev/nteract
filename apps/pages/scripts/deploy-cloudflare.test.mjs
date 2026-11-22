import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { cloudflareConfig } from "./cloudflare-stage.mjs";
import {
  bootstrapDigest,
  checkFrame,
  checkNoRoutes,
  withoutCiWorkerBinding,
} from "./deploy-cloudflare.mjs";
import { generateKeyring } from "./cloudflare-session-keys.mjs";
import { parseKeyring } from "./deployment/session-keys.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const receipt = { output_frame_path: "/frame/v2/" };
const vars = (frame) => ({
  vars: {
    NOTEBOOK_CLOUD_PUBLIC_ORIGIN: "https://app.example.com",
    PAGES_OUTPUT_FRAME_URL: frame,
  },
});

test("the bootstrap digest is the one attribute-free script's text", () => {
  const body = "console.log(1)";
  assert.equal(
    bootstrapDigest(`<html><script>${body}</script></html>`),
    createHash("sha256").update(body).digest("hex"),
  );
  assert.throws(() => bootstrapDigest("<script>a</script><script>b</script>"));
  assert.throws(() => bootstrapDigest('<script src="x">a</script>'));
  assert.throws(() => bootstrapDigest("<html></html>"));
});

test("the frame URL must be this build's path on another origin", () => {
  assert.equal(
    checkFrame(vars("https://frames.example.net/frame/v2/"), receipt).href,
    "https://frames.example.net/frame/v2/",
  );
  assert.throws(() => checkFrame(vars("https://frames.example.net/frame/v1/"), receipt), /path/);
  assert.throws(
    () => checkFrame(vars("https://app.example.com/frame/v2/"), receipt),
    /different origin/,
  );
  assert.throws(() =>
    checkFrame({ vars: { NOTEBOOK_CLOUD_PUBLIC_ORIGIN: "https://a.example.com" } }, receipt),
  );
});

test("a deployment that would attach a route or DNS record is refused", () => {
  assert.throws(() => checkNoRoutes({ custom_domain: { hostname: "a.b.c" } }, ""), /custom_domain/);
  assert.throws(
    () => checkNoRoutes({}, 'routes = [{ pattern = "x.example", custom_domain = true }]'),
    /routes/,
  );
  assert.throws(() => checkNoRoutes({}, "workers_dev = true"), /routes/);
  checkNoRoutes({}, "# No route: attach by hand\nworkers_dev = false\n");
});

test("a generated keyring is valid and new each time", () => {
  const a = parseKeyring(generateKeyring());
  assert.equal(a.active, "k1");
  assert.notEqual(a.keys.k1, parseKeyring(generateKeyring()).keys.k1);
});

test("the susu-prod deployment is valid, names a real frame and attaches no route", () => {
  const directory = path.join(here, "../deploy/susu-prod");
  const profile = JSON.parse(readFileSync(path.join(directory, "profile.json"), "utf8"));
  const output = readFileSync(path.join(directory, "wrangler.output.toml"), "utf8");
  checkNoRoutes(profile, output);
  const config = cloudflareConfig(profile);
  assert.equal(config.routes, undefined);
  assert.equal(config.workers_dev, false);
  assert.equal(config.vars.NOTEBOOK_CLOUD_PUBLIC_ORIGIN, "https://app.susu.dev");
  assert.equal(checkFrame(profile, receipt).origin, "https://pages.sususercontent.com");
  assert.match(output, /no_bundle = true/);
  assert.match(output, /^name = "pages-outputs"$/m);
});

test("the output Worker is not bound to the Worker the CI build is connected to", () => {
  const env = { PATH: "/bin", WRANGLER_CI_OVERRIDE_NAME: "pages", WRANGLER_CI_MATCH_TAG: "abc" };
  assert.deepEqual(withoutCiWorkerBinding(env), { PATH: "/bin" });
  assert.equal(env.WRANGLER_CI_OVERRIDE_NAME, "pages");
});
