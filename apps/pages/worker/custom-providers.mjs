/** Where this deployment's sign-in providers plug into the gateway.
 *
 * The gateway and the OAuth routes call these three functions and nothing
 * else of ours, so a provider added here needs no edit to `index.mjs` or
 * `oauth.mjs`, and a merge from upstream only has to keep the hook lines.
 * Order is the order providers are tried; the first to answer wins. */
import {
  authsuClientDocumentResponse,
  handleAuthsuSignIn,
  authsuSessionProvider,
} from "./authsu-signin.mjs";
import { handleKiloSignIn, kiloSessionProvider } from "./kilo-handoff.mjs";

/** The renewal provider for this deployment's browser sessions, or undefined
 * when it signs in with plain OIDC. Every caller of `serverOidcSessionStatus`
 * for a browser session passes this, so a provider-issued session is never
 * renewed through the generic OIDC path. */
export function browserSessionProvider(env, request) {
  return authsuSessionProvider(env, request) ?? kiloSessionProvider(env, request);
}

/** Answers `/api/auth/login` and `/oidc` for a provider that owns them, or
 * null so the generic OIDC routes answer. */
export async function handleProviderSignIn(request, env) {
  return (await handleAuthsuSignIn(request, env)) ?? (await handleKiloSignIn(request, env));
}

/** Answers GET requests for documents a provider fetches from this
 * deployment (authsu's client metadata), or null. Runs before the OAuth
 * routes, which answer every other `/oauth/` path with a 404. */
export function handleProviderDocument(request, env) {
  return authsuClientDocumentResponse(request, env);
}
