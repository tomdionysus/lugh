import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { Messages, useAct, useConfirm, useLoad } from "@lugh/admin-ui";

import useAPI from "../hooks/useAPI";

// One group: its name, its members, and the scopes it grants them. The scopes are written whole,
// against the version they were read at, and shown as a diff before they are saved.
export default function GroupDetail() {
	const { id = "" } = useParams();
	const api = useAPI();
	const navigate = useNavigate();
	const { value: read, error: loadError, reload } = useLoad(() => api.group(id), [id]);
	const { value: members, reload: reloadMembers } = useLoad(() => api.members(id), [id]);
	const { value: everyone } = useLoad(api.users);
	const { value: granted, reload: reloadScopes } = useLoad(() => api.groupScopes(id), [id]);
	const { value: known } = useLoad(api.scopes);
	const { act, error, message } = useAct(async () => {
		await Promise.all([reload(), reloadMembers(), reloadScopes()]);
	});
	const { ask, dialog } = useConfirm();
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");
	const [adding, setAdding] = useState("");
	const [scopes, setScopes] = useState<string[]>([]);
	const [extra, setExtra] = useState("");

	useEffect(() => {
		if (read) {
			setName(read.value.name);
			setDescription(read.value.description);
		}
	}, [read]);
	useEffect(() => {
		if (granted) setScopes(granted.value);
	}, [granted]);

	if (!read) return <div className="page">{loadError ? <p className="form-error">{loadError}</p> : <p className="muted">Loading</p>}</div>;

	const memberIds = new Set((members ?? []).map(user => user.id));
	const candidates = (everyone ?? []).filter(user => !memberIds.has(user.id));
	const before = new Set(granted?.value ?? []);
	const after = new Set(scopes);
	const added = scopes.filter(scope => !before.has(scope));
	const removed = [...before].filter(scope => !after.has(scope));
	const offered = [...new Set([...(known?.lugh ?? []), ...(known?.oidc ?? []), ...scopes])];

	return (
		<div className="page">
			<div className="page-header">
				<h2>{read.value.name}</h2>
			</div>
			<Messages error={error} message={message} />

			<section className="panel">
				<h3>Details</h3>
				<div className="form-grid">
					<label className="field">
						<span>Name</span>
						<input value={name} onChange={e => setName(e.target.value)} />
					</label>
					<label className="field">
						<span>Description</span>
						<input value={description} onChange={e => setDescription(e.target.value)} />
					</label>
				</div>
				<div className="form-actions">
					<button type="button" className="btn primary" onClick={() => act(() => api.updateGroup(id, { name, description }, read.etag), "Saved")}>
						Save
					</button>
					<button
						type="button"
						className="btn danger"
						onClick={() =>
							ask("Remove this group?", <p>Its members lose what it grants.</p>, "Remove", () =>
								act(async () => {
									await api.removeGroup(id, read.etag);
									navigate("/groups");
								}),
							)
						}
					>
						Remove
					</button>
				</div>
			</section>

			<section className="panel">
				<h3>Members</h3>
				<table className="data-table">
					<tbody>
						{members?.map(user => (
							<tr key={user.id}>
								<td>
									<Link to={`/users/${encodeURIComponent(user.id)}`}>{user.display_name || user.name}</Link>
								</td>
								<td>
									<button type="button" className="btn danger" onClick={() => act(() => api.removeMember(id, user.id), "Removed from the group")}>
										Remove
									</button>
								</td>
							</tr>
						))}
					</tbody>
				</table>
				<div className="form-actions">
					<select value={adding} onChange={e => setAdding(e.target.value)} aria-label="User to add">
						<option value="">Add someone</option>
						{candidates.map(user => (
							<option key={user.id} value={user.id}>
								{user.display_name || user.name}
							</option>
						))}
					</select>
					<button type="button" className="btn" disabled={!adding} onClick={() => act(() => api.addMember(id, adding), "Added").then(() => setAdding(""))}>
						Add
					</button>
				</div>
			</section>

			<section className="panel">
				<h3>Scopes it grants</h3>
				<p>A member's scopes are the union over their groups, read again within a minute of a change.</p>
				<div className="chips">
					{offered.map(scope => (
						<label key={scope} className="checkbox">
							<input type="checkbox" checked={after.has(scope)} onChange={e => setScopes(e.target.checked ? [...scopes, scope] : scopes.filter(one => one !== scope))} />
							<code>{scope}</code>
						</label>
					))}
				</div>
				<div className="form-actions">
					<input placeholder="Another scope, as app:read or lir:sub:topic/#" value={extra} onChange={e => setExtra(e.target.value.trim())} />
					<button
						type="button"
						className="btn"
						disabled={!extra || after.has(extra)}
						onClick={() => {
							setScopes([...scopes, extra]);
							setExtra("");
						}}
					>
						Add scope
					</button>
				</div>
				{(added.length > 0 || removed.length > 0) && (
					<div className="notice">
						<span>
							{added.map(scope => (
								<span key={scope} className="form-saved">
									+ <code>{scope}</code>{" "}
								</span>
							))}
							{removed.map(scope => (
								<span key={scope} className="form-error">
									- <code>{scope}</code>{" "}
								</span>
							))}
						</span>
						<button
							type="button"
							className="btn primary"
							onClick={() => act(() => api.setGroupScopes(id, [...after].sort(), granted?.etag ?? "*"), "Scopes saved")}
						>
							Save scopes
						</button>
					</div>
				)}
			</section>
			{dialog}
		</div>
	);
}
