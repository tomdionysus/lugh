import { useState } from "react";
import { useNavigate } from "react-router";

import { Messages, useAct, useLoad } from "@lugh/admin-ui";

import useAPI from "../hooks/useAPI";

// Every group, and a way to add one. What a group grants and who is in it are on its own page.
export default function Groups() {
	const api = useAPI();
	const navigate = useNavigate();
	const { value: groups, error: loadError, reload } = useLoad(api.groups);
	const { act, error, message } = useAct(reload);
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");

	const add = (event: React.FormEvent) => {
		event.preventDefault();
		act(async () => {
			const made = await api.createGroup(name, description);
			navigate(`/groups/${encodeURIComponent(made.id)}`);
		});
	};

	return (
		<div className="page">
			<div className="page-header">
				<h2>Groups</h2>
			</div>
			<Messages loadError={loadError} error={error} message={message} />
			<section className="panel">
				<table className="data-table">
					<thead>
						<tr>
							<th>Group</th>
							<th>Description</th>
						</tr>
					</thead>
					<tbody>
						{groups?.map(group => (
							<tr key={group.id} className="link" onClick={() => navigate(`/groups/${encodeURIComponent(group.id)}`)}>
								<td>{group.name}</td>
								<td className="muted">{group.description}</td>
							</tr>
						))}
					</tbody>
				</table>
			</section>
			<form className="panel" onSubmit={add}>
				<h3>Add a group</h3>
				<div className="form-grid">
					<label className="field">
						<span>Name</span>
						<input value={name} required onChange={e => setName(e.target.value)} />
					</label>
					<label className="field">
						<span>Description</span>
						<input value={description} onChange={e => setDescription(e.target.value)} />
					</label>
				</div>
				<div className="form-actions">
					<button type="submit" className="btn primary">
						Add group
					</button>
				</div>
			</form>
		</div>
	);
}
