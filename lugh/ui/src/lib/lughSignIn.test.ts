import { describe, expect, it } from "vitest";

import { challengeOf, finishLughSignIn, lughSignInUrl } from "./lughSignIn";

const config = { authorizationEndpoint: "https://lugh.example/oauth2/authorize", clientId: "lir-admin", redirectUri: "https://lir.example/admin/signed-in" };

function memory(): Storage {
	const items = new Map<string, string>();
	return {
		get length() {
			return items.size;
		},
		clear: () => items.clear(),
		getItem: key => items.get(key) ?? null,
		key: index => [...items.keys()][index] ?? null,
		removeItem: key => void items.delete(key),
		setItem: (key, value) => void items.set(key, value),
	};
}

describe("challengeOf", () => {
	it("is S256 of the verifier, as RFC 7636's appendix B works it", async () => {
		expect(await challengeOf("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
	});
});

describe("lughSignInUrl", () => {
	it("asks Lugh for a code with a fresh S256 challenge and state, and keeps the verifier for the way back", async () => {
		const storage = memory();
		const url = new URL(await lughSignInUrl(config, storage));
		expect(url.origin + url.pathname).toBe(config.authorizationEndpoint);
		expect(url.searchParams.get("response_type")).toBe("code");
		expect(url.searchParams.get("client_id")).toBe("lir-admin");
		expect(url.searchParams.get("redirect_uri")).toBe(config.redirectUri);
		expect(url.searchParams.get("scope")).toBe("openid");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		const kept = JSON.parse(storage.getItem("lugh-sign-in")!);
		expect(url.searchParams.get("state")).toBe(kept.state);
		expect(url.searchParams.get("code_challenge")).toBe(await challengeOf(kept.verifier));
		expect(kept.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);

		const again = new URL(await lughSignInUrl(config, memory()));
		expect(again.searchParams.get("state")).not.toBe(url.searchParams.get("state"));
	});
});

describe("finishLughSignIn", () => {
	it("gives the code and the verifier back for the state sent, once", async () => {
		const storage = memory();
		const state = new URL(await lughSignInUrl(config, storage)).searchParams.get("state")!;
		const kept = JSON.parse(storage.getItem("lugh-sign-in")!);
		expect(finishLughSignIn(`?code=c0de&state=${state}`, storage)).toEqual({ code: "c0de", codeVerifier: kept.verifier, redirectUri: config.redirectUri });
		expect(finishLughSignIn(`?code=c0de&state=${state}`, storage)).toEqual({ error: "no sign-in by Lugh was started here" });
	});

	it("refuses another state, a missing code, and says Lugh's refusal", async () => {
		const storage = memory();
		await lughSignInUrl(config, storage);
		expect(finishLughSignIn("?code=c0de&state=forged", storage)).toEqual({ error: "the sign-in came back with another state" });

		const state = new URL(await lughSignInUrl(config, storage)).searchParams.get("state")!;
		expect(finishLughSignIn(`?state=${state}`, storage)).toEqual({ error: "the sign-in came back without a code" });

		await lughSignInUrl(config, storage);
		expect(finishLughSignIn("?error=access_denied&error_description=the+person+declined", storage)).toEqual({ error: "Lugh refused the sign-in: the person declined" });
	});
});
