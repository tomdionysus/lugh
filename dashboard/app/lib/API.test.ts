import { describe, expect, it, vi } from "vitest";

import { API, ApiError, PHR, signInUrl } from "./API";

// What Lugh would answer, and what was asked of it.
function lugh(answers: Record<string, () => Response>) {
	const asked: { method: string; path: string; headers: Record<string, string>; body?: string }[] = [];
	const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const path = String(input);
		const method = init?.method ?? "GET";
		asked.push({ method, path, headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body as string | undefined });
		const answer = answers[`${method} ${path}`];
		if (!answer) return new Response(JSON.stringify({ error: { code: "not_found", message: "no such endpoint" } }), { status: 404, headers: { "content-type": "application/json" } });
		return answer();
	});
	return { api: new API(fetcher as unknown as typeof fetch), asked };
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) => () =>
	new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

const ME = {
	user: { id: "u1", name: "alice" },
	scopes: ["lugh:directory.read"],
	session: { acr: "urn:lugh:acr:mfa", auth_time: "2026-11-16T00:00:00Z", csrf_token: "tok3n" },
};

describe("API", () => {
	it("sends a change with the session's CSRF token, read from /api/v1/me first", async () => {
		const { api, asked } = lugh({ "GET /api/v1/me": json(ME), "POST /api/v1/groups": json({ id: "g1", name: "ops" }, 201) });
		const made = await api.createGroup("ops", "");
		expect(made.id).toBe("g1");
		expect(asked.map(one => `${one.method} ${one.path}`)).toEqual(["GET /api/v1/me", "POST /api/v1/groups"]);
		expect(asked[1].headers["X-CSRF-Token"]).toBe("tok3n");
		expect(JSON.parse(asked[1].body!)).toEqual({ name: "ops", description: "" });
	});

	it("never sends the token on a read", async () => {
		const { api, asked } = lugh({ "GET /api/v1/me": json(ME), "GET /api/v1/users": json({ users: [] }) });
		await api.me();
		await api.users();
		expect(asked[1].headers["X-CSRF-Token"]).toBeUndefined();
	});

	it("answers a read with its version, and sends it back as If-Match", async () => {
		const { api, asked } = lugh({
			"GET /api/v1/me": json(ME),
			"GET /api/v1/users/u%2F1": json({ id: "u/1", name: "bob" }, 200, { etag: '"7"' }),
			"PATCH /api/v1/users/u%2F1": json({ id: "u/1", name: "rob" }, 200, { etag: '"8"' }),
		});
		const read = await api.user("u/1");
		expect(read.etag).toBe('"7"');
		await api.updateUser("u/1", { name: "rob" }, read.etag);
		expect(asked.at(-1)!.headers["If-Match"]).toBe('"7"');
	});

	it("turns Lugh's error into an ApiError with its code", async () => {
		const { api } = lugh({
			"GET /api/v1/me": json(ME),
			"POST /api/v1/users": json({ error: { code: "duplicate", message: "the name alice is taken" } }, 409),
		});
		const refused = await api.createUser({ name: "alice" }).catch(e => e);
		expect(refused).toBeInstanceOf(ApiError);
		expect(refused.status).toBe(409);
		expect(refused.code).toBe("duplicate");
		expect(refused.message).toBe("the name alice is taken");
	});

	it("tells the layout when the session has ended, and when administering needs a passkey", async () => {
		const { api } = lugh({
			"GET /api/v1/users": json({ error: { code: "unauthorized", message: "a credential is needed" } }, 401),
			"GET /api/v1/groups": json({ error: { code: "phr_required", message: "administering needs a passkey" } }, 403),
		});
		const ended = vi.fn();
		const stepUp = vi.fn();
		api.onUnauthorised = ended;
		api.onStepUp = stepUp;
		await expect(api.users()).rejects.toThrow();
		expect(ended).toHaveBeenCalledTimes(1);
		await expect(api.groups()).rejects.toThrow();
		expect(stepUp).toHaveBeenCalledTimes(1);
	});

	it("refuses an answer that is not Lugh's JSON", async () => {
		const { api } = lugh({ "GET /api/v1/users": () => new Response("<html>a proxy's page</html>", { status: 502, headers: { "content-type": "text/html" } }) });
		const refused = await api.users().catch(e => e);
		expect(refused.code).toBe("not_json");
	});

	it("reads each list from the member Lugh answers it in", async () => {
		const { api } = lugh({
			"GET /api/v1/groups/g1/members": json({ members: [{ id: "u1", name: "alice" }] }),
			"GET /api/v1/me/app-passwords": json({ app_passwords: [{ id: "p1", name: "mail" }] }),
			"GET /api/v1/keys": json({ keys: [{ kid: "k1" }] }),
		});
		expect((await api.members("g1")).map(user => user.name)).toEqual(["alice"]);
		expect((await api.myAppPasswords()).map(one => one.name)).toEqual(["mail"]);
		expect((await api.keys()).map(key => key.kid)).toEqual(["k1"]);
	});

	it("answers 204 with nothing", async () => {
		const { api } = lugh({ "GET /api/v1/me": json(ME), "PUT /api/v1/groups/g1/members/u1": () => new Response(null, { status: 204 }) });
		await expect(api.addMember("g1", "u1")).resolves.toBeUndefined();
	});
});

describe("signInUrl", () => {
	it("comes back to the dashboard, and asks for phr to step up", () => {
		expect(signInUrl()).toBe("/signin?continue=dashboard");
		expect(signInUrl(true)).toBe("/signin?continue=dashboard&acr=" + encodeURIComponent(PHR));
	});
});
