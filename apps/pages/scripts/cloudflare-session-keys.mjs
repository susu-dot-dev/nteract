#!/usr/bin/env node
// One-off: set a deployment's session keyring as a Worker secret. A deploy
// (scripts/deploy-cloudflare.mjs) never reads or changes secrets, so run this
// once per deployment, and again only to rotate (DEPLOYMENT.md, "Session key
// rotation", "On Cloudflare").
//
//   node scripts/cloudflare-session-keys.mjs DEPLOYMENT_DIR --file KEYRING.json
//   node scripts/cloudflare-session-keys.mjs DEPLOYMENT_DIR --file KEYRING.json --generate
//
// `--file` names a keyring: {"active":"k1","keys":{"k1":"<32+ bytes>"}}.
// With `--generate` the file must not exist; the script writes a new keyring
// there (mode 0600) first. Workers secrets are write-only, so keep the file in
// the team's secret store. The script validates the keyring before it sends
// anything, refuses to replace a secret that is already set unless `--replace`
// is given (a new key signs every session out), and passes the value to
// Wrangler on stdin, never in an argument.
//
// The Worker must exist: run it after the first deploy. Until the secret is
// set the Worker answers every request with 500 server_misconfigured.
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { SESSION_KEYS_VAR, parseKeyring } from "./deployment/session-keys.mjs";

const app = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const wrangler = path.join(app, "node_modules/.bin/wrangler");

/** A new one-key keyring, as the text to store. */
export function generateKeyring(now = new Date()) {
  const keyring = {
    active: "k1",
    keys: { k1: randomBytes(48).toString("base64") },
    activated_at: { k1: now.toISOString() },
  };
  parseKeyring(JSON.stringify(keyring));
  return JSON.stringify(keyring);
}

function secretNames(name, account) {
  const out = execFileSync(wrangler, ["secret", "list", "--name", name, "--format", "json"], {
    cwd: app,
    encoding: "utf8",
    env: { ...process.env, ...(account && { CLOUDFLARE_ACCOUNT_ID: account }) },
  });
  return JSON.parse(out).map((secret) => secret.name);
}

export function main(argv) {
  const flags = new Set(["--generate", "--replace"]);
  const fileAt = argv.indexOf("--file");
  const file = fileAt === -1 ? undefined : argv[fileAt + 1];
  const rest = argv.filter((arg, i) => !flags.has(arg) && arg !== "--file" && i !== fileAt + 1);
  if (rest.length !== 1 || !file)
    throw new Error(
      "Usage: cloudflare-session-keys.mjs DEPLOYMENT_DIR --file KEYRING.json [--generate] [--replace]",
    );
  const profile = JSON.parse(
    readFileSync(path.join(path.resolve(rest[0]), "profile.json"), "utf8"),
  );
  const target = path.resolve(file);
  if (argv.includes("--generate")) {
    if (existsSync(target)) throw new Error(`${target} exists; refusing to overwrite a keyring`);
    writeFileSync(target, generateKeyring(), { mode: 0o600, flag: "wx" });
    console.log(`Wrote a new keyring to ${target}. Keep a copy in the secret store.`);
  }
  const keyring = readFileSync(target, "utf8");
  parseKeyring(keyring);

  if (
    !argv.includes("--replace") &&
    secretNames(profile.name, profile.account_id).includes(SESSION_KEYS_VAR)
  )
    throw new Error(
      `${SESSION_KEYS_VAR} is already set on ${profile.name}; pass --replace to rotate it`,
    );

  execFileSync(wrangler, ["secret", "put", SESSION_KEYS_VAR, "--name", profile.name], {
    cwd: app,
    input: keyring,
    stdio: ["pipe", "inherit", "inherit"],
    env: {
      ...process.env,
      ...(profile.account_id && { CLOUDFLARE_ACCOUNT_ID: profile.account_id }),
    },
  });
  console.log(`Set ${SESSION_KEYS_VAR} on ${profile.name}.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
