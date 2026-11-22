#!/usr/bin/env node
// Deploy one Cloudflare deployment of this build: the output (user frame)
// Worker first, then the Pages Worker. A deployment is a directory holding
//
//   profile.json           the profile cloudflare-stage.mjs reads
//   wrangler.output.toml   the output Worker's Wrangler file
//
// (see deploy/susu-prod). The default run changes nothing: it stages the Pages
// Worker, dry-runs both deploys and checks the receipt against the profile.
// `--apply` deploys, then checks the live frame shell and the Pages Worker.
//
//   node scripts/deploy-cloudflare.mjs deploy/susu-prod [--apply] [--secrets-file F]
//
// The tree must be clean and `npm run build` must have run on it
// (cleanBuildDist). The output Worker deploys before the Pages Worker, so a
// viewer never mounts a frame path the shell doesn't serve
// (DEPLOYMENT.md, "Deployment-neutral release package"). Session keys are never
// read from the profile: pass them with `--secrets-file`, which Wrangler
// applies additively, so a later deploy without it keeps what is set.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { cleanBuildDist, prepareCloudflare } from "./cloudflare-stage.mjs";

const app = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const wrangler = path.join(app, "node_modules/.bin/wrangler");
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** The frame document's one attribute-free script, hashed, as the installer
 * checks it for celld targets. Throws when the document has another shape. */
export function bootstrapDigest(html) {
  const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)];
  if (scripts.length !== 1 || scripts[0][1] !== "")
    throw new Error("The frame document must hold exactly one attribute-free script");
  return sha256(scripts[0][2]);
}

/** Refuse a profile whose frame URL isn't the path this build's viewer
 * mounts, or whose frame origin is the app's. Returns the frame URL. */
export function checkFrame(profile, receipt) {
  const { NOTEBOOK_CLOUD_PUBLIC_ORIGIN: origin, PAGES_OUTPUT_FRAME_URL: frame } = profile.vars;
  if (!frame) throw new Error("Profile vars need PAGES_OUTPUT_FRAME_URL");
  const url = new URL(frame);
  if (url.pathname !== receipt.output_frame_path)
    throw new Error(
      `PAGES_OUTPUT_FRAME_URL path ${url.pathname} is not the path this build mounts, ${receipt.output_frame_path}`,
    );
  if (url.origin === new URL(origin).origin)
    throw new Error("The frame shell must be on a different origin from the app");
  return url;
}

async function get(url) {
  const response = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(15_000) });
  return { status: response.status, text: await response.text() };
}

function run(args, options = {}) {
  console.log(`$ wrangler ${args.join(" ")}`);
  execFileSync(wrangler, args, { cwd: app, stdio: "inherit", ...options });
}

/** Retry until the new deployment answers: a custom domain's certificate and
 * DNS can take a minute after the first deploy. */
async function eventually(label, check) {
  let last;
  for (let attempt = 0; attempt < 24; attempt++) {
    try {
      return await check();
    } catch (error) {
      last = error;
      await new Promise((resolve) => setTimeout(resolve, 5_000));
    }
  }
  throw new Error(`${label}: ${last?.message ?? last}`);
}

export async function main(argv) {
  const args = argv.slice();
  const apply = args.includes("--apply");
  const secretsIndex = args.indexOf("--secrets-file");
  const secrets = secretsIndex === -1 ? undefined : path.resolve(args[secretsIndex + 1] ?? "");
  const rest = args.filter(
    (arg, index) => arg !== "--apply" && arg !== "--secrets-file" && index !== secretsIndex + 1,
  );
  if (rest.length !== 1 || (secretsIndex !== -1 && !args[secretsIndex + 1]))
    throw new Error("Usage: deploy-cloudflare.mjs DEPLOYMENT_DIR [--apply] [--secrets-file FILE]");
  const directory = path.resolve(rest[0]);
  const profile = JSON.parse(readFileSync(path.join(directory, "profile.json"), "utf8"));
  const outputConfig = path.join(directory, "wrangler.output.toml");
  if (!existsSync(outputConfig)) throw new Error(`${outputConfig} is missing`);
  if (secrets && !existsSync(secrets)) throw new Error(`${secrets} is missing`);

  const dist = cleanBuildDist();
  const receipt = JSON.parse(readFileSync(path.join(dist, "build-receipt.json"), "utf8"));
  const frame = checkFrame(profile, receipt);
  const origin = profile.vars.NOTEBOOK_CLOUD_PUBLIC_ORIGIN;

  const stage = path.join(mkdtempSync(path.join(os.tmpdir(), "pages-cloudflare-")), "release");
  const appConfig = prepareCloudflare(stage, profile);
  console.log(`Build ${receipt.build_id} staged at ${stage}`);

  run(["deploy", "--config", outputConfig, "--dry-run"]);
  run([
    "deploy",
    "--config",
    appConfig,
    "--dry-run",
    ...(secrets ? ["--secrets-file", secrets] : []),
  ]);
  if (!apply) {
    console.log("Dry run only. Pass --apply to deploy.");
    return;
  }

  run(["deploy", "--config", outputConfig]);
  await eventually("output Worker", async () => {
    const health = await get(new URL("/health", frame.origin));
    if (health.status !== 200 || health.text.trim() !== `pages-output-v2 ${receipt.build_id}`)
      throw new Error(`/health answered ${health.status} ${health.text.trim().slice(0, 80)}`);
    const shell = await get(frame);
    if (shell.status !== 200) throw new Error(`${frame.pathname} answered ${shell.status}`);
    if (bootstrapDigest(shell.text) !== receipt.output_frame_bootstrap_sha256)
      throw new Error("The frame bootstrap differs from this build's receipt");
  });
  console.log(`Output Worker serves ${frame.href} at build ${receipt.build_id}`);

  run(["deploy", "--config", appConfig, ...(secrets ? ["--secrets-file", secrets] : [])]);
  await eventually("Pages Worker", async () => {
    const health = await get(new URL("/health", origin));
    if (health.status !== 200) throw new Error(`/health answered ${health.status}`);
    const home = await get(new URL("/", origin));
    if (home.status !== 200 || !home.text.includes(frame.href))
      throw new Error(`The app shell does not name ${frame.href}`);
  });
  console.log(`Pages Worker answers at ${origin}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
