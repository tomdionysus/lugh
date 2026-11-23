import { useState } from "react";
import { useNavigate } from "react-router";

import { Messages, useAct, useLoad } from "@lugh/admin-ui";

import useAPI from "../hooks/useAPI";
import type { NewUser } from "../lib/API";

const EMPTY: NewUser = { kind: "person", name: "", email: "", display_name: "" };

// Everyone in the directory, people and services, and a way to add one. A new person starts not
// enrolled: their enrolment link is on their own page.
export default function Users() {
	const api = useAPI();
	const navigate = useNavigate();
	const { value: users, error: loadError, reload } = useLoad(api.users);
	const { act, error, message } = useAct(reload);
	const [draft, setDraft] = useState<NewUser>(EMPTY);
	const [filter, setFilter] = useState("");

	const add = (event: React.FormEvent) => {
		event.preventDefault();
		act(async () => {
			const made = await api.createUser(draft);
			setDraft(EMPTY);
			navigate(`/users/${encodeURIComponent(made.id)}`);
		});
	};

	const shown = (users ?? []).filter(user => !filter || `${user.name} ${user.display_name} ${user.email}`.toLowerCase().includes(filter.toLowerCase()));

	return (
		<div className="page">
			<div className="page-header">
				<h2>Users</h2>
				<input placeholder="Find" value={filter} onChange={e => setFilter(e.target.value)} aria-label="Find a user" />
			</div>
			<Messages loadError={loadError} error={error} message={message} />

			<section className="panel">
				<table className="data-table">
					<thead>
						<tr>
							<th>User</th>
							<th>Address</th>
							<th>Kind</th>
							<th>State</th>
						</tr>
					</thead>
					<tbody>
						{shown.map(user => (
							<tr key={user.id} className="link" onClick={() => navigate(`/users/${encodeURIComponent(user.id)}`)}>
								<td>
									{user.display_name || user.name}
									<div className="muted">
										<code>{user.name}</code>
									</div>
								</td>
								<td>{user.email}</td>
								<td>{user.kind}</td>
								<td>
									{user.disabled ? (
										<span className="pill bad">Disabled</span>
									) : user.kind === "service" || user.enrolled ? (
										<span className="pill good">Active</span>
									) : (
										<span className="pill warn">Not enrolled</span>
									)}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</section>

			<form className="panel" onSubmit={add}>
				<h3>Add a user</h3>
				<div className="form-grid">
					<label className="field">
						<span>Kind</span>
						<select value={draft.kind} onChange={e => setDraft({ ...draft, kind: e.target.value as NewUser["kind"] })}>
							<option value="person">Person</option>
							<option value="service">Service</option>
						</select>
					</label>
					<label className="field">
						<span>Name</span>
						<input value={draft.name} required autoCapitalize="none" spellCheck={false} onChange={e => setDraft({ ...draft, name: e.target.value })} />
					</label>
					<label className="field">
						<span>Address</span>
						<input type="email" value={draft.email} required={draft.kind === "person"} onChange={e => setDraft({ ...draft, email: e.target.value })} />
					</label>
					<label className="field">
						<span>Display name</span>
						<input value={draft.display_name} onChange={e => setDraft({ ...draft, display_name: e.target.value })} />
					</label>
				</div>
				<div className="form-actions">
					<button type="submit" className="btn primary">
						Add user
					</button>
				</div>
			</form>
		</div>
	);
}
