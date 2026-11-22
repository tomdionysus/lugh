import { PHR, type AuditEntry, type Group, type Me, type User } from "../lib/API";

// Lugh's API as the dashboard calls it, in memory, for the component tests: the person signed in,
// users and groups made and joined, and what the audit log records of it. Each answer has the shape
// docs/api.md gives; a path it does not know answers Lugh's 404.

type Answer = { status: number; body?: unknown; etag?: string };

const NOW = "2026-11-22T12:00:00Z";

export class FakeLugh {
	me: Me;
	users: User[] = [];
	groups: Group[] = [];
	members = new Map<string, string[]>();
	audit: AuditEntry[] = [];
	// Every request, "METHOD /path", in order.
	asked: string[] = [];
	private _next = 1;

	constructor(acr: string = PHR) {
		const root = this._user({ name: "root", display_name: "Root", enrolled: true });
		this.me = {
			user: root,
			scopes: ["lugh:directory.read", "lugh:directory.write", "lugh:audit.read"],
			session: { acr, auth_time: NOW, csrf_token: "csrf-t0ken" },
		};
	}

	// The fetch the dashboard's API is given: globalThis.fetch, stubbed.
	fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
		const url = new URL(String(input), "https://lugh.test");
		const method = init?.method ?? "GET";
		this.asked.push(`${method} ${url.pathname}`);
		const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
		const answer = this._answer(method, url.pathname.split("/").map(decodeURIComponent), body);
		if (answer.status === 204) return new Response(null, { status: 204 });
		const headers: Record<string, string> = { "content-type": "application/json" };
		if (answer.etag) headers.etag = answer.etag;
		return new Response(JSON.stringify(answer.body), { status: answer.status, headers });
	};

	private _answer(method: string, path: string[], body: any): Answer {
		const [, api, v1, what, id, sub, subId] = path;
		if (api !== "api" || v1 !== "v1") return missing();
		// Users and groups are named by id (/users/:id/groups, /groups/:id/members/:sub); every other
		// path is literal (/me/factors, /audit/verify).
		const named = what === "users" || what === "groups";
		const route = named
			? `${method} ${what}${id === undefined ? "" : "/:id"}${sub === undefined ? "" : "/" + sub}${subId === undefined ? "" : "/:sub"}`
			: `${method} ${path.slice(3).join("/")}`;
		switch (route) {
			case "GET me":
				return ok(this.me);
			case "GET me/factors":
				return ok({ factors: [{ id: "f1", kind: "webauthn", confirmed: true, created_at: NOW, name: "", aaguid: "", backed_up: true, last_used_at: NOW }] });
			case "GET me/sessions":
				return ok({ sessions: [{ sid: "s1", acr: this.me.session!.acr, amr: ["hwk"], signed_in_at: NOW, last_seen_at: NOW, current: true }] });
			case "GET me/app-passwords":
				return ok({ app_passwords: [] });
			case "GET users":
				return ok({ users: this.users });
			case "POST users": {
				const user = this._user({ name: body.name, email: body.email ?? "", display_name: body.display_name ?? "", kind: body.kind ?? "person" });
				this._record("user.create", user.id);
				return { status: 201, body: user, etag: '"1"' };
			}
			case "GET users/:id": {
				const user = this.users.find(one => one.id === id);
				return user ? { status: 200, body: user, etag: '"1"' } : missing();
			}
			case "GET users/:id/groups":
				return ok({ groups: this.groups.filter(group => (this.members.get(group.id) ?? []).includes(id)) });
			case "GET users/:id/factors":
				return ok({ factors: [] });
			case "GET users/:id/sessions":
				return ok({ sessions: [] });
			case "POST users/:id/enrolment":
				this._record("enrolment.issue", id);
				return ok({ token: "l1nk", expires_at: NOW });
			case "GET groups":
				return ok({ groups: this.groups });
			case "POST groups": {
				const group: Group = { id: `g${this._next++}`, name: body.name, description: body.description ?? "", created_at: NOW, updated_at: NOW };
				this.groups.push(group);
				this._record("group.create", group.id);
				return { status: 201, body: group, etag: '"1"' };
			}
			case "GET groups/:id": {
				const group = this.groups.find(one => one.id === id);
				return group ? { status: 200, body: group, etag: '"1"' } : missing();
			}
			case "GET groups/:id/members":
				return ok({ members: this.users.filter(user => (this.members.get(id) ?? []).includes(user.id)) });
			case "PUT groups/:id/members/:sub":
				this.members.set(id, [...(this.members.get(id) ?? []), subId]);
				this._record("group.member.add", `${id} ${subId}`);
				return { status: 204 };
			case "GET groups/:id/scopes":
				return { status: 200, body: { scopes: [] }, etag: '"1"' };
			case "GET scopes":
				return ok({ lugh: ["lugh:directory.read", "lugh:audit.read"], oidc: ["openid"] });
			case "GET audit":
				return ok({ entries: this.audit, next: null });
			case "GET audit/verify":
				return ok({ intact: true, entries: this.audit.length });
			default:
				return missing();
		}
	}

	private _user(fields: Partial<User>): User {
		const user: User = {
			id: `u${this._next++}`,
			kind: "person",
			name: "",
			email: "",
			display_name: "",
			given_name: "",
			family_name: "",
			enrolled: false,
			disabled: false,
			created_at: NOW,
			updated_at: NOW,
			...fields,
		};
		this.users.push(user);
		return user;
	}

	private _record(action: string, subject: string) {
		const sequence = this.audit.length + 1;
		this.audit.push({ sequence, time: NOW, action, actor: this.me.user.id, subject, source: "192.0.2.1", detail: "", hash: `h${sequence}`, previous: `h${sequence - 1}` });
	}
}

const ok = (body: unknown): Answer => ({ status: 200, body });
const missing = (): Answer => ({ status: 404, body: { error: { code: "not_found", message: "no such endpoint" } } });
