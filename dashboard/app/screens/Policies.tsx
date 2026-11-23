import { Messages, useAct, useConfirm, useLoad } from "@lugh/admin-ui";

import useAPI from "../hooks/useAPI";
import { MFA, PHR, PWD } from "../lib/API";
import { assurance } from "../lib/format";

const LEVELS = [PWD, MFA, PHR];

// How sure Lugh must be of a person before they are signed in: everyone's level, and a group's
// own, which can only raise it. Each change is shown as it will be, before it is made.
export default function Policies() {
	const api = useAPI();
	const { value: policies, error: loadError, reload } = useLoad(api.policies);
	const { value: groups } = useLoad(api.groups);
	const { act, error, message } = useAct(reload);
	const { ask, dialog } = useConfirm();

	const nameOf = (id: string) => groups?.find(group => group.id === id)?.name ?? id;
	const levelOf = (group: string) => policies?.groups.find(one => one.group === group)?.acr ?? "";

	const change = (what: string, from: string, to: string, run: () => Promise<unknown>) =>
		ask(
			"Change the sign-in policy?",
			<p>
				{what}: {from ? assurance(from) : "as everyone"} becomes {to ? assurance(to) : "as everyone"}. Sign-ins from now on need it.
			</p>,
			"Change",
			() => act(run, "Policy changed"),
			false,
		);

	return (
		<div className="page">
			<div className="page-header">
				<h2>Policies</h2>
			</div>
			<Messages loadError={loadError} error={error} message={message} />
			{policies && (
				<section className="panel">
					<h3>Everyone</h3>
					<div className="form-actions">
						<select
							value={policies.global}
							onChange={e => {
								const to = e.target.value;
								change("Everyone", policies.global, to, () => api.setGlobalPolicy(to));
							}}
							aria-label="Everyone's level"
						>
							{LEVELS.map(level => (
								<option key={level} value={level}>
									{assurance(level)}
								</option>
							))}
						</select>
					</div>
				</section>
			)}
			<section className="panel">
				<h3>Groups</h3>
				<table className="data-table">
					<thead>
						<tr>
							<th>Group</th>
							<th>Level</th>
						</tr>
					</thead>
					<tbody>
						{groups?.map(group => (
							<tr key={group.id}>
								<td>{nameOf(group.id)}</td>
								<td>
									<select
										value={levelOf(group.id)}
										onChange={e => {
											const to = e.target.value;
											change(group.name, levelOf(group.id), to, () => api.setGroupPolicy(group.id, to || null));
										}}
										aria-label={`${group.name}'s level`}
									>
										<option value="">As everyone</option>
										{LEVELS.map(level => (
											<option key={level} value={level}>
												{assurance(level)}
											</option>
										))}
									</select>
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</section>
			{dialog}
		</div>
	);
}
