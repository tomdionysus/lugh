// Signing in by Lugh, the stack's directory: OpenID Connect's authorization code flow with PKCE
// (RFC 7636, S256). The browser goes to Lugh with a challenge and a state, and comes back with a
// code; the service's own back end exchanges the code and the verifier for tokens and gives the
// browser its session, so no token is ever held in the browser (the shape Lugh's dashboard has).

export type LughSignInConfig = {
	// Lugh's authorization endpoint, from its discovery document (/.well-known/openid-configuration).
	authorizationEndpoint: string;
	clientId: string;
	// Where Lugh sends the browser back: the service's page that calls finishLughSignIn().
	redirectUri: string;
	scope?: string;
};

// What the service's back end exchanges for its session.
export type LughCode = { code: string; codeVerifier: string; redirectUri: string };

const KEY = "lugh-sign-in";

function base64url(bytes: Uint8Array): string {
	let text = "";
	for (const byte of bytes) text += String.fromCharCode(byte);
	return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function random(count: number): string {
	return base64url(crypto.getRandomValues(new Uint8Array(count)));
}

// The S256 challenge of a verifier.
export async function challengeOf(verifier: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
	return base64url(new Uint8Array(digest));
}

// Where the browser goes to sign in by Lugh; the verifier and state are kept in `storage` for the
// way back. 32 random bytes of verifier, 16 of state.
export async function lughSignInUrl(config: LughSignInConfig, storage: Storage = sessionStorage): Promise<string> {
	const verifier = random(32);
	const state = random(16);
	storage.setItem(KEY, JSON.stringify({ verifier, state, redirectUri: config.redirectUri }));
	const url = new URL(config.authorizationEndpoint);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", config.clientId);
	url.searchParams.set("redirect_uri", config.redirectUri);
	url.searchParams.set("scope", config.scope ?? "openid");
	url.searchParams.set("state", state);
	url.searchParams.set("code_challenge", await challengeOf(verifier));
	url.searchParams.set("code_challenge_method", "S256");
	return url.toString();
}

// The way back from Lugh (the redirect page's query): the code and the verifier for the service's back
// end, or why not. The state must be the one sent, and is good once.
export function finishLughSignIn(search: string, storage: Storage = sessionStorage): LughCode | { error: string } {
	const answer = new URLSearchParams(search);
	const kept = storage.getItem(KEY);
	storage.removeItem(KEY);
	if (answer.get("error")) return { error: `Lugh refused the sign-in: ${answer.get("error_description") || answer.get("error")}` };
	if (!kept) return { error: "no sign-in by Lugh was started here" };
	const { verifier, state, redirectUri } = JSON.parse(kept) as { verifier: string; state: string; redirectUri: string };
	if (answer.get("state") !== state) return { error: "the sign-in came back with another state" };
	const code = answer.get("code");
	if (!code) return { error: "the sign-in came back without a code" };
	return { code, codeVerifier: verifier, redirectUri };
}
