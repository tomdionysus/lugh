import { describe, expect, it, vi } from "vitest";

import { ApiClient, ApiError } from "./api";

// A service, as a test says it answers, and what was asked of it.
function service(answers: Record<string, () => Response>) {
	const asked: { method: string; url: string; headers: Record<string, string> }[] = [];
	const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = String(input);
		const method = init?.method ?? "GET";
		asked.push({ method, url, headers: (init?.headers ?? {}) as Record<string, string> });
		const answer = answers[`${method} ${url}`];
		if (!answer) return new Response(JSON.stringify({ error: { code: "not_found", message: "no such endpoint" } }), { status: 404, headers: { "content-type": "application/json" } });
		return answer();
	});
	return { fetcher: fetcher as unknown as typeof fetch, asked };
}

const json = (body: unknown, status = 200) => () => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// A consumer's client: a read, a change, and its session read for the CSRF token.
class Louhi extends ApiClient {
	sessionReads = 0;
	status = async () => (await this.send<{ state: string }>("GET", "/api/status")).value;
	restart = () => this.change<void>("POST", "/api/restart", {});
	protected override async ensureCsrf() {
		this.sessionReads += 1;
		this.setCsrf("t0ken");
	}
}

describe("ApiClient", () => {
	it("puts every path under its base", async () => {
		const { fetcher, asked } = service({ "GET /admin/api/status": json({ state: "up" }) });
		expect((await new Louhi("/admin", fetcher).status()).state).toBe("up");
		expect(asked[0].url).toBe("/admin/api/status");
	});

	it("reads the session for a CSRF token before the first change, and sends it with each change only", async () => {
		const { fetcher, asked } = service({ "GET /api/status": json({ state: "up" }), "POST /api/restart": () => new Response(null, { status: 204 }) });
		const louhi = new Louhi("", fetcher);
		await louhi.restart();
		await louhi.restart();
		await louhi.status();
		expect(louhi.sessionReads).toBe(1);
		expect(asked[0].headers["X-CSRF-Token"]).toBe("t0ken");
		expect(asked[2].headers["X-CSRF-Token"]).toBeUndefined();
	});

	it("forgets the token and says so on 401, and passes a 403's code on", async () => {
		const { fetcher } = service({
			"POST /api/restart": json({ error: { code: "unauthorized", message: "signed out" } }, 401),
			"GET /api/status": json({ error: { code: "phr_required", message: "a passkey is needed" } }, 403),
		});
		const louhi = new Louhi("", fetcher);
		const ended = vi.fn();
		const forbidden = vi.fn();
		louhi.onUnauthorised = ended;
		louhi.onForbidden = forbidden;
		const refused = await louhi.restart().catch(e => e);
		expect(refused).toBeInstanceOf(ApiError);
		expect(refused.status).toBe(401);
		expect(ended).toHaveBeenCalledTimes(1);
		await louhi.restart().catch(() => {});
		expect(louhi.sessionReads).toBe(2);
		await louhi.status().catch(() => {});
		expect(forbidden).toHaveBeenCalledWith("phr_required");
	});

	it("refuses an answer that is not JSON, naming the URL", async () => {
		const { fetcher } = service({ "GET /api/status": () => new Response("<html>a proxy's page</html>", { status: 502, headers: { "content-type": "text/html" } }) });
		const refused = await new Louhi("", fetcher).status().catch(e => e);
		expect(refused.code).toBe("not_json");
		expect(refused.message).toContain("/api/status");
	});
});
