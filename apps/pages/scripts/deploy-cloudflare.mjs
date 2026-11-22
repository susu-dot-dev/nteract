// Deploy one Cloudflare deployment of this build: the output (user frame)
// Worker first, then the Pages Worker. It is the deploy command for
// Cloudflare Workers Builds (or any CI) on a repository checkout:
//
//   build command   npm run setup && npm run build
//   deploy command  node scripts/deploy-cloudflare.mjs deploy/susu-prod
//   root directory  apps/pages
//
// A deployment is a directory holding
//
//   profile.json           the profile cloudflare-stage.mjs reads
//   wrangler.output.toml   the output Worker's Wrangler file
//
// (see deploy/susu-prod). The script only deploys code and configuration
// that the commit decides. It never creates a DNS record or route, and it
// never touches a secret: attach the domains once in the dashboard or with
// Wrangler, and set the session keyring once with
// scripts/cloudflare-session-keys.mjs. A deploy keeps both. Plain variables
// come from the profile on every deploy, so a variable set only in the
// dashboard is removed.
//
// The tree must be clean and `npm run build` must have run on it
// (cleanBuildDist). The output Worker deploys before the Pages Worker, so a
// viewer never mounts a frame path the shell doesn't serve
// (DEPLOYMENT.md, "Deployment-neutral release package").
//
//   --dry-run   stage and dry-run both deploys; upload nothing. Use it as a
//               non-production branch command.
//   --verify    after deploying, check the live frame shell and the app over
//               their public origins. They answer only once the domains are
//               attached, so leave it off for the first deploy.
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

/** Refuse a deployment that would create a route or DNS record. Domains are
 * attached by hand, so a deploy never changes where the Workers are served. */
export function checkNoRoutes(profile, outputConfigText) {
  if (profile.custom_domain !== undefined)
    throw new Error("Remove custom_domain from the profile: this script never creates a route");
  if (/^\s*(routes?|workers_dev\s*=\s*true)\b/m.test(outputConfigText))
    throw new Error("Remove routes from wrangler.output.toml: this script never creates a route");
}

export async function main(argv) {
  const dryRun = argv.includes("--dry-run");
  const verify = argv.includes("--verify");
  const rest = argv.filter((arg) => arg !== "--dry-run" && arg !== "--verify");
  if (rest.length !== 1 || (dryRun && verify))
    throw new Error("Usage: deploy-cloudflare.mjs DEPLOYMENT_DIR [--dry-run | --verify]");
  const directory = path.resolve(rest[0]);
  const profile = JSON.parse(readFileSync(path.join(directory, "profile.json"), "utf8"));
  const outputConfig = path.join(directory, "wrangler.output.toml");
  if (!existsSync(outputConfig)) throw new Error(`${outputConfig} is missing`);
  checkNoRoutes(profile, readFileSync(outputConfig, "utf8"));

  const dist = cleanBuildDist();
  const receipt = JSON.parse(readFileSync(path.join(dist, "build-receipt.json"), "utf8"));
  const frame = checkFrame(profile, receipt);
  const origin = profile.vars.NOTEBOOK_CLOUD_PUBLIC_ORIGIN;

  const stage = path.join(mkdtempSync(path.join(os.tmpdir(), "pages-cloudflare-")), "release");
  const appConfig = prepareCloudflare(stage, profile);
  console.log(`Build ${receipt.build_id} staged at ${stage}`);

  if (dryRun) {
    run(["deploy", "--config", outputConfig, "--dry-run"]);
    run(["deploy", "--config", appConfig, "--dry-run"]);
    console.log("Dry run only; nothing was uploaded.");
    return;
  }

  run(["deploy", "--config", outputConfig]);
  run(["deploy", "--config", appConfig]);
  console.log(`Deployed build ${receipt.build_id}: ${profile.name} and the output Worker.`);
  if (!verify) return;

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
