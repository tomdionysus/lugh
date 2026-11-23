// The one way an admin UI talks to its service. Same origin by default: the service serves the UI,
// and under `vite dev` Vite forwards the service's paths to it, so a session cookie is simply sent
// and no token is held here. `base` puts every path under a prefix (Louhi's /admin, say). A change
// carries the session's CSRF token once the service has given it (setCsrf); a change to something
// versioned carries the ETag it was read with.

export type Versioned<T> = { value: T; etag: string };

export class ApiError extends Error {
	constructor(
		public status: number,
		public code: string,
		message: string,
	) {
		super(message);
	}
}

export function errorOf(error: unknown): string {
	if (error instanceof Error) return error.message;
	return String(error);
}

const json = (body: unknown) => (body === undefined ? undefined : JSON.stringify(body));

export class ApiClient {
	// Told when the service answers 401: the session has ended, wherever that was noticed.
	onUnauthorised: () => void = () => {};
	// Told when the service answers 403, with its error code: a step-up the UI may offer.
	onForbidden: (code: string) => void = () => {};

	private _csrf: string | undefined;

	constructor(
		protected readonly base: string = "",
		private readonly _fetch: typeof fetch = (...args) => fetch(...args),
	) {}

	// The session's CSRF token, as the service gave it; undefined when it has ended.
	setCsrf(token: string | undefined) {
		this._csrf = token;
	}

	protected hasCsrf() {
		return this._csrf !== undefined;
	}

	// Called before a change when no CSRF token is held: a subclass reads the session (which sets it).
	protected async ensureCsrf(): Promise<void> {}

	// A change: a CSRF token first, then the request; the answer's value.
	protected async change<T = void>(method: string, path: string, body?: unknown, etag?: string): Promise<T> {
		if (!this.hasCsrf()) await this.ensureCsrf();
		return (await this.send<T>(method, path, body, etag)).value;
	}

	// One request: JSON both ways, the service's error shape ({ error: { code, message } }) as an
	// ApiError, 204 as no value.
	protected async send<T>(method: string, path: string, body?: unknown, etag?: string): Promise<Versioned<T>> {
		const headers: Record<string, string> = { Accept: "application/json" };
		if (body !== undefined) headers["Content-Type"] = "application/json";
		if (method !== "GET" && method !== "HEAD" && this._csrf) headers["X-CSRF-Token"] = this._csrf;
		if (etag !== undefined) headers["If-Match"] = etag;
		const url = this.base + path;
		const response = await this._fetch(url, { method, credentials: "same-origin", headers, body: json(body) });
		const version = response.headers.get("etag") ?? "";

		if (response.status === 204) return { value: undefined as T, etag: version };

		// The service answers JSON on every API path; anything else is not the service.
		const type = response.headers.get("content-type") ?? "";
		if (!type.startsWith("application/json")) throw new ApiError(response.status, "not_json", `${url} did not answer JSON`);

		const parsed = await response.json();
		if (!response.ok) {
			const code: string = parsed?.error?.code ?? "unknown";
			if (response.status === 401) {
				this._csrf = undefined;
				this.onUnauthorised();
			}
			if (response.status === 403) this.onForbidden(code);
			throw new ApiError(response.status, code, parsed?.error?.message ?? response.statusText);
		}
		return { value: parsed as T, etag: version };
	}
}
