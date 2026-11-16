import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { useConfirm } from "../components/Confirm";
import Messages from "../components/Messages";
import useAct from "../hooks/useAct";
import useAPI from "../hooks/useAPI";
import useLoad from "../hooks/useLoad";
import type { User, UserChange } from "../lib/API";
import { assurance, when } from "../lib/format";

// One user: their details (with the version they were read at), their groups, their factors,
// their sessions, and what an administrator may do about each.
export default function UserDetail() {
	const { id = "" } = useParams();
	const api = useAPI();
	const navigate = useNavigate();
	const { value: read, error: loadError, reload } = useLoad(() => api.user(id), [id]);
	const { value: groups, reload: reloadGroups } = useLoad(() => api.userGroups(id), [id]);
	const { value: factors, reload: reloadFactors } = useLoad(() => api.userFactors(id), [id]);
	const { value: sessions, reload: reloadSessions } = useLoad(() => api.userSessions(id), [id]);
	const { act, error, message } = useAct(async () => {
		await Promise.all([reload(), reloadGroups(), reloadFactors(), reloadSessions()]);
	});
	const { ask, dialog } = useConfirm();
	const [edit, setEdit] = useState<UserChange>({});
	const [link, setLink] = useState<{ token: string; expires_at: string } | undefined>(undefined);

	useEffect(() => {
		if (read) setEdit({ name: read.value.name, email: read.value.email, display_name: read.value.display_name });
	}, [read]);

	if (!read) return <div className="page">{loadError ? <p className="form-error">{loadError}</p> : <p className="muted">Loading</p>}</div>;
	const user: User = read.value;

	return (
		<div className="page">
			<div className="page-header">
				<h2>{user.display_name || user.name}</h2>
				<div className="actions">
					{user.disabled ? (
						<span className="pill bad">Disabled</span>
					) : user.kind === "person" && !user.enrolled ? (
						<span className="pill warn">Not enrolled</span>
					) : (
						<span className="pill good">Active</span>
					)}
				</div>
			</div>
			<Messages error={error} message={message} />

			<section className="panel">
				<h3>Details</h3>
				<div className="form-grid">
					<label className="field">
						<span>Name</span>
						<input value={edit.name ?? ""} onChange={e => setEdit({ ...edit, name: e.target.value })} />
					</label>
					<label className="field">
						<span>Address</span>
						<input type="email" value={edit.email ?? ""} onChange={e => setEdit({ ...edit, email: e.target.value })} />
					</label>
					<label className="field">
						<span>Display name</span>
						<input value={edit.display_name ?? ""} onChange={e => setEdit({ ...edit, display_name: e.target.value })} />
					</label>
					<div className="field">
						<span>Since</span>
						<span>{when(user.created_at)}</span>
					</div>
				</div>
				<div className="form-actions">
					<button type="button" className="btn primary" onClick={() => act(() => api.updateUser(id, edit, read.etag), "Saved")}>
						Save
					</button>
					<button
						type="button"
						className="btn"
						onClick={() =>
							user.disabled
								? act(() => api.updateUser(id, { disabled: false }, read.etag), "Enabled")
								: ask("Disable this user?", <p>{user.name} is signed out everywhere and cannot sign in until enabled again.</p>, "Disable", () =>
										act(() => api.updateUser(id, { disabled: true }, read.etag), "Disabled"),
									)
						}
					>
						{user.disabled ? "Enable" : "Disable"}
					</button>
					<button
						type="button"
						className="btn danger"
						onClick={() =>
							ask("Remove this user?", <p>{user.name}, their memberships, password and factors go for good.</p>, "Remove", () =>
								act(async () => {
									await api.removeUser(id, read.etag);
									navigate("/users");
								}),
							)
						}
					>
						Remove
					</button>
				</div>
			</section>

			<section className="panel">
				<h3>Groups</h3>
				{groups && groups.length === 0 && <p className="muted">In no group.</p>}
				<div className="chips">
					{groups?.map(group => (
						<Link key={group.id} className="pill" to={`/groups/${encodeURIComponent(group.id)}`}>
							{group.name}
						</Link>
					))}
				</div>
			</section>

			{user.kind === "person" && (
				<section className="panel">
					<h3>Factors</h3>
					{factors && factors.length === 0 && <p className="muted">None: they enrol through a link.</p>}
					{factors && factors.length > 0 && (
						<table className="data-table">
							<tbody>
								{factors.map(factor => (
									<tr key={factor.id}>
										<td>{factor.kind === "webauthn" ? factor.name || "Passkey" : factor.kind === "totp" ? "Authenticator app" : `Recovery codes, ${factor.remaining ?? 0} left`}</td>
										<td>{when(factor.created_at)}</td>
										<td>
											<button
												type="button"
												className="btn danger"
												onClick={() => ask("Remove this factor?", <p>It will no longer sign {user.name} in.</p>, "Remove", () => act(() => api.removeUserFactor(id, factor.id), "Removed"))}
											>
												Remove
											</button>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					)}
					<div className="form-actions">
						<button type="button" className="btn" onClick={() => act(async () => setLink(await api.enrolmentLink(id)), "Enrolment link made")}>
							Make an enrolment link
						</button>
						<button
							type="button"
							className="btn danger"
							onClick={() =>
								ask(
									"Reset every factor?",
									<p>For someone who has lost them all: every factor goes, every session ends, and {user.name} must enrol again through a new link.</p>,
									"Reset",
									() => act(() => api.resetFactors(id), "Factors reset"),
								)
							}
						>
							Reset factors
						</button>
					</div>
					{link && (
						<div className="notice">
							<span>
								Give them this, once; it works until {when(link.expires_at)}:
							</span>
							<span className="secret-once">
								{window.location.origin}/signin/enrol/{link.token}
							</span>
						</div>
					)}
				</section>
			)}

			<section className="panel">
				<h3>Sessions</h3>
				{sessions && sessions.length === 0 && <p className="muted">Not signed in anywhere.</p>}
				{sessions && sessions.length > 0 && (
					<>
						<table className="data-table">
							<thead>
								<tr>
									<th>Signed in</th>
									<th>How</th>
									<th>Last seen</th>
								</tr>
							</thead>
							<tbody>
								{sessions.map(session => (
									<tr key={session.sid}>
										<td>{when(session.signed_in_at)}</td>
										<td>{assurance(session.acr)}</td>
										<td>{when(session.last_seen_at)}</td>
									</tr>
								))}
							</tbody>
						</table>
						<div className="form-actions">
							<button type="button" className="btn danger" onClick={() => act(() => api.endUserSessions(id), "Signed out everywhere")}>
								Sign out everywhere
							</button>
						</div>
					</>
				)}
			</section>
			{dialog}
		</div>
	);
}
