import { useState } from "react";

import { ApiError, Messages, useAct, useConfirm, useLoad, when } from "@lugh/admin-ui";

import QrCode from "../components/QrCode";
import useAPI from "../hooks/useAPI";
import { useSigned } from "../layouts/AdminLayout";
import type { Factor, TotpSetup } from "../lib/API";
import { assurance } from "../lib/format";
import { assert, available, register } from "../lib/webauthn";

const MINIMUM_PASSWORD = 12;

// A person's own account, whatever they may administer: their factors (behind the
// re-authentication window), where they are signed in, their password and their app passwords.
export default function Account() {
	const { me } = useSigned();
	return (
		<div className="page">
			<div className="page-header">
				<h2>{me.user.display_name || me.user.name}</h2>
				<span className="muted">
					<code>{me.user.name}</code> {me.user.email && <>&middot; {me.user.email}</>}
				</span>
			</div>
			<Factors />
			<Sessions />
			<Password />
			<AppPasswords scopes={me.scopes} />
		</div>
	);
}

function describe(factor: Factor): string {
	switch (factor.kind) {
		case "webauthn":
			return factor.name || "Passkey";
		case "totp":
			return factor.confirmed ? "Authenticator app" : "Authenticator app, not yet confirmed";
		case "recovery":
			return `Recovery codes, ${factor.remaining ?? 0} left`;
	}
}

// The factors, and every change to them behind a window a factor opens (ten minutes).
function Factors() {
	const api = useAPI();
	const { value: factors, error: loadError, reload } = useLoad(api.myFactors);
	const { act, error, message } = useAct(reload);
	const { ask, dialog } = useConfirm();
	const [code, setCode] = useState("");
	const [openUntil, setOpenUntil] = useState<number | undefined>(undefined);
	const [setup, setSetup] = useState<TotpSetup | undefined>(undefined);
	const [confirmCode, setConfirmCode] = useState("");
	const [keyName, setKeyName] = useState("Passkey");
	const [codes, setCodes] = useState<string[] | undefined>(undefined);
	const [renaming, setRenaming] = useState<{ id: string; name: string } | undefined>(undefined);

	const open = openUntil !== undefined && Date.now() < openUntil;
	const hasKey = factors?.some(factor => factor.kind === "webauthn") ?? false;

	// A change outside the window asks for a factor first.
	const changing = (what: () => Promise<unknown>, done: string) =>
		act(async () => {
			try {
				await what();
			} catch (e) {
				if (e instanceof ApiError && e.code === "reauthentication_required") setOpenUntil(undefined);
				throw e;
			}
		}, done);

	const opened = (seconds: number) => setOpenUntil(Date.now() + seconds * 1000);

	return (
		<section className="panel">
			<h3>Sign-in factors</h3>
			<Messages loadError={loadError} error={error} message={message} />
			<table className="data-table">
				<thead>
					<tr>
						<th>Factor</th>
						<th>Added</th>
						<th>Last used</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{factors?.map(factor => (
						<tr key={factor.id}>
							<td>
								{renaming?.id === factor.id ? (
									<input value={renaming.name} maxLength={64} onChange={e => setRenaming({ id: factor.id, name: e.target.value })} />
								) : (
									describe(factor)
								)}
								{factor.kind === "webauthn" && factor.backed_up && <div className="muted">Synced passkey</div>}
							</td>
							<td>{when(factor.created_at)}</td>
							<td>{when(factor.last_used_at)}</td>
							<td>
								<div className="form-actions">
									{factor.kind === "webauthn" &&
										(renaming?.id === factor.id ? (
											<button
												type="button"
												className="btn"
												disabled={!open || !renaming.name}
												onClick={() => changing(() => api.renameKey(factor.id, renaming.name), "Renamed").then(ok => ok && setRenaming(undefined))}
											>
												Save
											</button>
										) : (
											<button type="button" className="btn" disabled={!open} onClick={() => setRenaming({ id: factor.id, name: factor.name ?? "" })}>
												Rename
											</button>
										))}
									<button
										type="button"
										className="btn danger"
										disabled={!open}
										onClick={() =>
											ask("Remove this factor?", <p>{describe(factor)} will no longer sign you in. Your last one stays while your policy needs it.</p>, "Remove", () =>
												changing(() => api.removeMyFactor(factor.id), "Removed"),
											)
										}
									>
										Remove
									</button>
								</div>
							</td>
						</tr>
					))}
				</tbody>
			</table>

			{!open && (
				<div className="form-actions">
					<span className="muted">To change your factors, prove one first:</span>
					<input inputMode="numeric" autoComplete="one-time-code" placeholder="Code from your app" value={code} onChange={e => setCode(e.target.value.trim())} />
					<button
						type="button"
						className="btn"
						disabled={code.length < 6}
						onClick={() =>
							act(async () => {
								opened((await api.reauthenticateWithCode(code)).expires_in);
								setCode("");
							}, "You may change your factors for ten minutes")
						}
					>
						Use code
					</button>
					{hasKey && available() && (
						<button
							type="button"
							className="btn"
							onClick={() =>
								act(async () => {
									const options = await api.ceremonyOptions("reauthenticate");
									opened((await api.reauthenticateWithKey(await assert(options))).expires_in);
								}, "You may change your factors for ten minutes")
							}
						>
							Use a passkey
						</button>
					)}
				</div>
			)}

			{open && (
				<div className="form-actions">
					{available() && (
						<>
							<input value={keyName} maxLength={64} onChange={e => setKeyName(e.target.value)} aria-label="Name for the new passkey" />
							<button
								type="button"
								className="btn primary"
								disabled={!keyName}
								onClick={() =>
									changing(async () => {
										const options = await api.ceremonyOptions("register");
										await api.addKey(await register(options, keyName));
									}, "Passkey added")
								}
							>
								Add a passkey
							</button>
						</>
					)}
					<button type="button" className="btn" onClick={() => changing(async () => setSetup(await api.addTotp()), "")}>
						Add an authenticator app
					</button>
					<button
						type="button"
						className="btn"
						onClick={() =>
							ask("Make new recovery codes?", <p>The codes you have now stop working.</p>, "Make new codes", () =>
								changing(async () => setCodes(await api.newRecoveryCodes()), "New recovery codes made"),
							)
						}
					>
						New recovery codes
					</button>
				</div>
			)}

			{setup && (
				<div className="panel">
					<h3>Add an authenticator app</h3>
					<p className="muted">Scan this with your app, or type the key into it, then type the code it shows. The key is shown only now.</p>
					{setup.qr && <QrCode size={setup.qr.size} modules={setup.qr.modules} label="The new authenticator's QR code" />}
					<div className="secret-once">{setup.secret}</div>
					<div className="form-actions">
						<input inputMode="numeric" autoComplete="one-time-code" placeholder="Code" value={confirmCode} onChange={e => setConfirmCode(e.target.value.trim())} />
						<button
							type="button"
							className="btn primary"
							disabled={confirmCode.length < 6}
							onClick={() =>
								changing(async () => {
									await api.confirmTotp(setup.id, confirmCode);
									setSetup(undefined);
									setConfirmCode("");
								}, "Authenticator app added")
							}
						>
							Confirm
						</button>
					</div>
				</div>
			)}

			{codes && (
				<div className="panel">
					<h3>Your recovery codes</h3>
					<p className="muted">Keep these somewhere safe. Each works once, and they are shown only now.</p>
					<div className="codes">
						{codes.map(one => (
							<span key={one}>{one}</span>
						))}
					</div>
					<div className="form-actions">
						<button type="button" className="btn" onClick={() => setCodes(undefined)}>
							I have kept them
						</button>
					</div>
				</div>
			)}
			{dialog}
		</section>
	);
}

function Sessions() {
	const api = useAPI();
	const { value: sessions, error: loadError, reload } = useLoad(api.mySessions);
	const { act, error, message } = useAct(reload);
	return (
		<section className="panel">
			<h3>Where you are signed in</h3>
			<Messages loadError={loadError} error={error} message={message} />
			<table className="data-table">
				<thead>
					<tr>
						<th>Signed in</th>
						<th>How</th>
						<th>Last seen</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{sessions?.map(session => (
						<tr key={session.sid}>
							<td>
								{when(session.signed_in_at)}
								{session.current && <span className="muted"> (this one)</span>}
							</td>
							<td>{assurance(session.acr)}</td>
							<td>{when(session.last_seen_at)}</td>
							<td>
								{!session.current && (
									<button type="button" className="btn danger" onClick={() => act(() => api.endMySession(session.sid), "Signed out there")}>
										Sign out
									</button>
								)}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</section>
	);
}

function Password() {
	const api = useAPI();
	const [current, setCurrent] = useState("");
	const [fresh, setFresh] = useState("");
	const { act, error, message } = useAct();
	const change = (event: React.FormEvent) => {
		event.preventDefault();
		act(async () => {
			await api.changePassword(current, fresh);
			setCurrent("");
			setFresh("");
		}, "Password changed; you are signed out everywhere else");
	};
	return (
		<form className="panel" onSubmit={change}>
			<h3>Password</h3>
			<Messages error={error} message={message} />
			<div className="form-grid">
				<label className="field">
					<span>Current password</span>
					<input type="password" autoComplete="current-password" value={current} required onChange={e => setCurrent(e.target.value)} />
				</label>
				<label className="field">
					<span>New password</span>
					<input type="password" autoComplete="new-password" value={fresh} required minLength={MINIMUM_PASSWORD} onChange={e => setFresh(e.target.value)} />
					<small>At least {MINIMUM_PASSWORD} characters.</small>
				</label>
			</div>
			<div className="form-actions">
				<button type="submit" className="btn primary">
					Change password
				</button>
			</div>
		</form>
	);
}

// Passwords for what cannot sign in through Lugh's pages (LDAP: mail, a NAS, a VPN), each with a
// subset of the person's own scopes.
function AppPasswords({ scopes }: { scopes: string[] }) {
	const api = useAPI();
	const { value: passwords, error: loadError, reload } = useLoad(api.myAppPasswords);
	const { act, error, message } = useAct(reload);
	const { ask, dialog } = useConfirm();
	const [name, setName] = useState("");
	const [chosen, setChosen] = useState<string[]>(scopes.includes("lugh:directory.read") ? ["lugh:directory.read"] : []);
	const [made, setMade] = useState<string | undefined>(undefined);

	const add = (event: React.FormEvent) => {
		event.preventDefault();
		act(async () => {
			const answer = await api.addMyAppPassword(name, chosen);
			setMade(answer.password);
			setName("");
		}, "App password made");
	};

	return (
		<section className="panel">
			<h3>App passwords</h3>
			<Messages loadError={loadError} error={error} message={message} />
			{made && (
				<div className="notice">
					<span>Shown only now:</span>
					<span className="secret-once">{made}</span>
					<button type="button" className="btn" onClick={() => setMade(undefined)}>
						Done
					</button>
				</div>
			)}
			{passwords && passwords.length > 0 && (
				<table className="data-table">
					<thead>
						<tr>
							<th>Name</th>
							<th>Scopes</th>
							<th>Made</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{passwords.map(password => (
							<tr key={password.id}>
								<td>{password.name}</td>
								<td>
									<code>{password.scopes.join(" ")}</code>
								</td>
								<td>{when(password.created_at)}</td>
								<td>
									<button
										type="button"
										className="btn danger"
										onClick={() =>
											ask("Revoke this app password?", <p>{password.name} stops working at once, connections already open included.</p>, "Revoke", () =>
												act(() => api.revokeMyAppPassword(password.id), "Revoked"),
											)
										}
									>
										Revoke
									</button>
								</td>
							</tr>
						))}
					</tbody>
				</table>
			)}
			<form onSubmit={add} className="form-actions">
				<input placeholder="Name, as mail on my laptop" value={name} required maxLength={64} onChange={e => setName(e.target.value)} />
				{scopes.map(scope => (
					<label key={scope} className="checkbox">
						<input
							type="checkbox"
							checked={chosen.includes(scope)}
							onChange={e => setChosen(e.target.checked ? [...chosen, scope] : chosen.filter(one => one !== scope))}
						/>
						<code>{scope}</code>
					</label>
				))}
				<button type="submit" className="btn">
					Make an app password
				</button>
			</form>
			{dialog}
		</section>
	);
}

