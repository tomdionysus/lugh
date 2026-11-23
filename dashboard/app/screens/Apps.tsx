import { useState } from "react";

import { Messages, useAct, useConfirm, useLoad, when } from "@lugh/admin-ui";

import useAPI from "../hooks/useAPI";
import type { App } from "../lib/API";
import { assurance } from "../lib/format";

// The applications that sign people in through Lugh, or call it themselves: each one's settings,
// which groups may use it, and its secret. Registering one asks only what every kind needs; the
// rest is in the API (docs/api.md, "Applications").
export default function Apps() {
	const api = useAPI();
	const { value: apps, error: loadError, reload } = useLoad(api.apps);
	const { value: groups } = useLoad(api.groups);
	const { act, error, message } = useAct(reload);
	const { ask, dialog } = useConfirm();
	const [open, setOpen] = useState<string | undefined>(undefined);
	const [secret, setSecret] = useState<string | undefined>(undefined);
	const [draft, setDraft] = useState({ name: "", kind: "spa", redirect: "" });

	const register = (event: React.FormEvent) => {
		event.preventDefault();
		const interactive = draft.kind === "spa" || draft.kind === "native" || draft.kind === "web";
		act(async () => {
			const made = await api.createApp({
				name: draft.name,
				kind: draft.kind,
				client_authentication: draft.kind === "spa" || draft.kind === "native" ? "none" : "client_secret_basic",
				grant_types: interactive ? ["authorization_code", "refresh_token"] : ["client_credentials"],
				redirect_uris: interactive && draft.redirect ? [draft.redirect] : [],
				scopes: interactive ? ["openid", "profile", "email"] : [],
			});
			if (made.client_secret) setSecret(made.client_secret);
			setDraft({ name: "", kind: "spa", redirect: "" });
			setOpen(made.client_id);
		}, "Application registered");
	};

	return (
		<div className="page">
			<div className="page-header">
				<h2>Applications</h2>
			</div>
			<Messages loadError={loadError} error={error} message={message} />
			{secret && (
				<div className="notice">
					<span>Its client secret, shown only now:</span>
					<span className="secret-once">{secret}</span>
					<button type="button" className="btn" onClick={() => setSecret(undefined)}>
						Done
					</button>
				</div>
			)}
			<section className="panel">
				<table className="data-table">
					<thead>
						<tr>
							<th>Application</th>
							<th>Kind</th>
							<th>Needs</th>
							<th>State</th>
						</tr>
					</thead>
					<tbody>
						{apps?.map(app => (
							<AppRow
								key={app.client_id}
								app={app}
								open={open === app.client_id}
								onToggle={() => setOpen(open === app.client_id ? undefined : app.client_id)}
								groups={groups ?? []}
								act={act}
								ask={ask}
								onSecret={setSecret}
							/>
						))}
					</tbody>
				</table>
			</section>
			<form className="panel" onSubmit={register}>
				<h3>Register an application</h3>
				<div className="form-grid">
					<label className="field">
						<span>Name</span>
						<input value={draft.name} required onChange={e => setDraft({ ...draft, name: e.target.value })} />
					</label>
					<label className="field">
						<span>Kind</span>
						<select value={draft.kind} onChange={e => setDraft({ ...draft, kind: e.target.value })}>
							<option value="spa">Single-page app</option>
							<option value="web">Web app with a server</option>
							<option value="native">Native app</option>
							<option value="service">Service</option>
						</select>
					</label>
					{draft.kind !== "service" && (
						<label className="field">
							<span>Redirect URI</span>
							<input type="url" value={draft.redirect} placeholder="https://app.example.com/callback" onChange={e => setDraft({ ...draft, redirect: e.target.value })} />
						</label>
					)}
				</div>
				<div className="form-actions">
					<button type="submit" className="btn primary">
						Register
					</button>
				</div>
			</form>
			{dialog}
		</div>
	);
}

function AppRow({
	app,
	open,
	onToggle,
	groups,
	act,
	ask,
	onSecret,
}: {
	app: App;
	open: boolean;
	onToggle: () => void;
	groups: { id: string; name: string }[];
	act: (what: () => Promise<unknown>, done?: string) => Promise<boolean>;
	ask: (title: string, body: React.ReactNode, action: string, run: () => void, danger?: boolean) => void;
	onSecret: (secret: string) => void;
}) {
	const api = useAPI();
	// Each change reads the application first, for the version it changes.
	const change = (fields: Record<string, unknown>, done: string) =>
		act(async () => {
			const current = await api.app(app.client_id);
			await api.updateApp(app.client_id, fields, current.etag);
		}, done);

	return (
		<>
			<tr className="link" onClick={onToggle}>
				<td>
					{app.name}
					<div className="muted">
						<code>{app.client_id}</code>
					</div>
				</td>
				<td>{app.kind}</td>
				<td>{app.acr ? assurance(app.acr) : <span className="muted">Policy</span>}</td>
				<td>{app.enabled ? <span className="pill good">Enabled</span> : <span className="pill bad">Disabled</span>}</td>
			</tr>
			{open && (
				<tr>
					<td colSpan={4}>
						<div className="panel">
							<p className="muted">Registered {when(app.created_at)}. Redirects to: {app.redirect_uris.join(", ") || "none"}.</p>
							<h3>Who may use it</h3>
							<div className="chips">
								{groups.map(group => (
									<label key={group.id} className="checkbox">
										<input
											type="checkbox"
											checked={app.access.includes(group.id)}
											onChange={e => act(() => api.allowGroup(app.client_id, group.id, e.target.checked), "Saved")}
										/>
										{group.name}
									</label>
								))}
							</div>
							<div className="form-actions">
								<button type="button" className="btn" onClick={() => change({ enabled: !app.enabled }, app.enabled ? "Disabled" : "Enabled")}>
									{app.enabled ? "Disable" : "Enable"}
								</button>
								{app.client_authentication === "client_secret_basic" && (
									<button
										type="button"
										className="btn"
										onClick={() =>
											ask("Make a new client secret?", <p>The one it has now keeps working for 24 hours.</p>, "Make one", () =>
												act(async () => onSecret((await api.newSecret(app.client_id)).client_secret), "New secret made"),
											false)
										}
									>
										New secret
									</button>
								)}
								<button
									type="button"
									className="btn danger"
									onClick={() =>
										ask("Remove this application?", <p>{app.name} stops working everywhere, and its client ID is never used again.</p>, "Remove", () =>
											act(async () => {
												const current = await api.app(app.client_id);
												await api.removeApp(app.client_id, current.etag);
											}, "Removed"),
										)
									}
								>
									Remove
								</button>
							</div>
						</div>
					</td>
				</tr>
			)}
		</>
	);
}
