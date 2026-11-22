import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { cloudflareConfig } from "./cloudflare-stage.mjs";
import { bootstrapDigest, checkFrame } from "./deploy-cloudflare.mjs";

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

test("the susu-prod profile is a valid deployment and names a real frame", () => {
  const directory = path.join(here, "../deploy/susu-prod");
  const profile = JSON.parse(readFileSync(path.join(directory, "profile.json"), "utf8"));
  const config = cloudflareConfig(profile);
  assert.deepEqual(config.routes, [
    { pattern: "app.susu.dev", zone_name: "susu.dev", custom_domain: true },
  ]);
  assert.equal(checkFrame(profile, receipt).origin, "https://sususercontent.com");
  const output = readFileSync(path.join(directory, "wrangler.output.toml"), "utf8");
  assert.match(output, /routes = \[\{ pattern = "sususercontent\.com", custom_domain = true \}\]/);
  assert.match(output, /no_bundle = true/);
});
