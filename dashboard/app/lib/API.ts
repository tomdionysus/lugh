import { ApiClient } from "@lugh/admin-ui";

export { ApiError, errorOf, type Versioned } from "@lugh/admin-ui";

// The one way the dashboard talks to Lugh (docs/api.md), on @lugh/admin-ui's ApiClient. Same origin
// always: lugh-node serves the dashboard, and under `npm run dev` Vite forwards Lugh's paths to it,
// so the session cookie is simply sent and no token is ever held here. A change carries the
// session's CSRF token, which /api/v1/me gives; a change to something versioned carries the ETag
// it was read with.

export const PWD = "urn:lugh:acr:pwd";
export const MFA = "urn:lugh:acr:mfa";
export const PHR = "urn:lugh:acr:phr";

export type User = {
	id: string;
	kind: "person" | "service";
	name: string;
	email: string;
	display_name: string;
	given_name: string;
	family_name: string;
	posix_number?: number;
	enrolled: boolean;
	disabled: boolean;
	created_at: string;
	updated_at: string;
};

export type NewUser = {
	kind?: "person" | "service";
	name: string;
	email?: string;
	display_name?: string;
	given_name?: string;
	family_name?: string;
};

export type UserChange = Partial<Pick<User, "name" | "email" | "display_name" | "given_name" | "family_name" | "disabled">>;

export type Group = {
	id: string;
	name: string;
	description: string;
	posix_number?: number;
	created_at: string;
	updated_at: string;
};

export type Session = {
	sid: string;
	acr: string;
	amr: string[];
	signed_in_at: string;
	last_seen_at: string;
	current: boolean;
};

export type Me = {
	user: User;
	scopes: string[];
	// Present when the caller is a session, as the dashboard always is.
	session?: { acr: string; auth_time: string; csrf_token: string };
};

export type Factor = {
	id: string;
	kind: "totp" | "recovery" | "webauthn";
	confirmed: boolean;
	created_at: string;
	remaining?: number;
	name?: string;
	aaguid?: string;
	backed_up?: boolean;
	last_used_at?: string | null;
};

export type TotpSetup = {
	id: string;
	secret: string;
	uri: string;
	// The QR symbol's modules, row by row, '1' dark.
	qr?: { size: number; modules: string };
};

export type AppPassword = {
	id: string;
	name: string;
	scopes: string[];
	networks: string[];
	created_at: string;
	password?: string;
};

export type Policies = { global: string; groups: { group: string; acr: string }[] };

export type App = {
	client_id: string;
	name: string;
	kind: "web" | "spa" | "native" | "service" | "api";
	scope_prefix?: string;
	client_authentication: string;
	redirect_uris: string[];
	grant_types: string[];
	scopes: string[];
	audiences: string[];
	client_scopes: string[];
	access: string[];
	roles: Record<string, string[]>;
	// The least assurance it needs; null: the person's policy alone.
	acr: string | null;
	enabled: boolean;
	first_party: boolean;
	created_at: string;
	updated_at: string;
	client_secret?: string;
	[field: string]: unknown;
};

export type SigningKey = { kid: string; algorithm: string; created_at: string; signing_from: string; retired_at: string | null };

export type AuditEntry = {
	sequence: number;
	time: string;
	action: string;
	actor: string;
	subject: string;
	source: string;
	detail: string;
	hash: string;
	previous: string;
};

// Where the browser goes to sign in, or to step up to a passkey, and comes back to the dashboard.
export function signInUrl(stepUp = false): string {
	return "/signin?continue=dashboard" + (stepUp ? "&acr=" + encodeURIComponent(PHR) : "");
}

const segment = encodeURIComponent;

export class API extends ApiClient {
	// Told when Lugh answers 403 phr_required: administering needs a passkey sign-in.
	onStepUp: () => void = () => {};

	constructor(fetcher?: typeof fetch) {
		super("", fetcher);
		this.onForbidden = code => {
			if (code === "phr_required") this.onStepUp();
		};
	}

	// The CSRF token comes with the session, from /api/v1/me.
	protected override async ensureCsrf() {
		await this.me();
	}

	me = async () => {
		const me = (await this.send<Me>("GET", "/api/v1/me")).value;
		this.setCsrf(me.session?.csrf_token);
		return me;
	};

	// The person's own.
	mySessions = async () => (await this.send<{ sessions: Session[] }>("GET", "/api/v1/me/sessions")).value.sessions;
	endMySession = (sid: string) => this.change("DELETE", `/api/v1/me/sessions/${segment(sid)}`);
	changePassword = (current: string, fresh: string) => this.change("POST", "/api/v1/me/password", { current, new: fresh });
	myFactors = async () => (await this.send<{ factors: Factor[] }>("GET", "/api/v1/me/factors")).value.factors;
	reauthenticateWithCode = (code: string) => this.change<{ expires_in: number }>("POST", "/api/v1/me/reauthenticate", { code });
	reauthenticateWithKey = (webauthn: Record<string, string>) => this.change<{ expires_in: number }>("POST", "/api/v1/me/reauthenticate", { webauthn });
	ceremonyOptions = (purpose: "reauthenticate" | "register") => this.change<Record<string, unknown>>("POST", "/api/v1/me/webauthn/options", { purpose });
	addTotp = () => this.change<TotpSetup>("POST", "/api/v1/me/factors/totp", {});
	confirmTotp = (id: string, code: string) => this.change("POST", `/api/v1/me/factors/totp/${segment(id)}/confirm`, { code });
	addKey = (registration: { name: string; challenge: string; client_data: string; attestation_object: string }) =>
		this.change<Factor>("POST", "/api/v1/me/factors/webauthn", registration);
	renameKey = (id: string, name: string) => this.change<Factor>("PATCH", `/api/v1/me/factors/${segment(id)}`, { name });
	removeMyFactor = (id: string) => this.change("DELETE", `/api/v1/me/factors/${segment(id)}`);
	newRecoveryCodes = async () => (await this.change<{ codes: string[] }>("POST", "/api/v1/me/factors/recovery", {})).codes;
	myAppPasswords = async () => (await this.send<{ app_passwords: AppPassword[] }>("GET", "/api/v1/me/app-passwords")).value.app_passwords;
	addMyAppPassword = (name: string, scopes: string[]) => this.change<AppPassword>("POST", "/api/v1/me/app-passwords", { name, scopes });
	revokeMyAppPassword = (id: string) => this.change("DELETE", `/api/v1/me/app-passwords/${segment(id)}`);

	// Users.
	users = async () => (await this.send<{ users: User[] }>("GET", "/api/v1/users")).value.users;
	user = (id: string) => this.send<User>("GET", `/api/v1/users/${segment(id)}`);
	createUser = (user: NewUser) => this.change<User>("POST", "/api/v1/users", user);
	updateUser = (id: string, change: UserChange, etag: string) => this.change<User>("PATCH", `/api/v1/users/${segment(id)}`, change, etag);
	removeUser = (id: string, etag: string) => this.change("DELETE", `/api/v1/users/${segment(id)}`, undefined, etag);
	userGroups = async (id: string) => (await this.send<{ groups: Group[] }>("GET", `/api/v1/users/${segment(id)}/groups`)).value.groups;
	userFactors = async (id: string) => (await this.send<{ factors: Factor[] }>("GET", `/api/v1/users/${segment(id)}/factors`)).value.factors;
	removeUserFactor = (id: string, factor: string) => this.change("DELETE", `/api/v1/users/${segment(id)}/factors/${segment(factor)}`);
	resetFactors = (id: string) => this.change("POST", `/api/v1/users/${segment(id)}/factors/reset`, {});
	enrolmentLink = (id: string) => this.change<{ token: string; expires_at: string }>("POST", `/api/v1/users/${segment(id)}/enrolment`, {});
	userSessions = async (id: string) => (await this.send<{ sessions: Session[] }>("GET", `/api/v1/users/${segment(id)}/sessions`)).value.sessions;
	endUserSessions = (id: string) => this.change<{ ended: number }>("DELETE", `/api/v1/users/${segment(id)}/sessions`);

	// Groups.
	groups = async () => (await this.send<{ groups: Group[] }>("GET", "/api/v1/groups")).value.groups;
	group = (id: string) => this.send<Group>("GET", `/api/v1/groups/${segment(id)}`);
	createGroup = (name: string, description: string) => this.change<Group>("POST", "/api/v1/groups", { name, description });
	updateGroup = (id: string, change: { name?: string; description?: string }, etag: string) =>
		this.change<Group>("PATCH", `/api/v1/groups/${segment(id)}`, change, etag);
	removeGroup = (id: string, etag: string) => this.change("DELETE", `/api/v1/groups/${segment(id)}`, undefined, etag);
	members = async (id: string) => (await this.send<{ members: User[] }>("GET", `/api/v1/groups/${segment(id)}/members`)).value.members;
	addMember = (id: string, user: string) => this.change("PUT", `/api/v1/groups/${segment(id)}/members/${segment(user)}`);
	removeMember = (id: string, user: string) => this.change("DELETE", `/api/v1/groups/${segment(id)}/members/${segment(user)}`);
	groupScopes = async (id: string) => {
		const read = await this.send<{ scopes: string[] }>("GET", `/api/v1/groups/${segment(id)}/scopes`);
		return { value: read.value.scopes, etag: read.etag };
	};
	setGroupScopes = (id: string, scopes: string[], etag: string) => this.change("PUT", `/api/v1/groups/${segment(id)}/scopes`, { scopes }, etag);
	scopes = async () => (await this.send<{ lugh: string[]; oidc: string[] }>("GET", "/api/v1/scopes")).value;

	// Policies.
	policies = async () => (await this.send<Policies>("GET", "/api/v1/policies")).value;
	setGlobalPolicy = (acr: string) => this.change("PUT", "/api/v1/policies/global", { acr });
	setGroupPolicy = (group: string, acr: string | null) => this.change("PUT", `/api/v1/policies/groups/${segment(group)}`, { acr });

	// Applications.
	apps = async () => (await this.send<{ apps: App[] }>("GET", "/api/v1/apps")).value.apps;
	app = (id: string) => this.send<App>("GET", `/api/v1/apps/${segment(id)}`);
	createApp = (app: Record<string, unknown>) => this.change<App>("POST", "/api/v1/apps", app);
	updateApp = (id: string, change: Record<string, unknown>, etag: string) => this.change<App>("PATCH", `/api/v1/apps/${segment(id)}`, change, etag);
	removeApp = (id: string, etag: string) => this.change("DELETE", `/api/v1/apps/${segment(id)}`, undefined, etag);
	allowGroup = (id: string, group: string, allowed: boolean) => this.change<App>(allowed ? "PUT" : "DELETE", `/api/v1/apps/${segment(id)}/access/${segment(group)}`);
	newSecret = (id: string) => this.change<{ client_secret: string; previous_secret_expires_at: string }>("POST", `/api/v1/apps/${segment(id)}/secret`, {});

	// Signing keys and the audit log.
	keys = async () => (await this.send<{ keys: SigningKey[] }>("GET", "/api/v1/keys")).value.keys;
	rotateKey = (algorithm: "ES256" | "EdDSA") => this.change("POST", "/api/v1/keys/rotate", { algorithm });
	audit = async (from = 1, limit = 100) =>
		(await this.send<{ entries: AuditEntry[]; next: number | null }>("GET", `/api/v1/audit?from=${from}&limit=${limit}`)).value;
	verifyAudit = async () => (await this.send<{ intact: boolean; entries?: number; problem?: string }>("GET", "/api/v1/audit/verify")).value;
}
