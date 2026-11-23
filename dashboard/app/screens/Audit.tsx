import { useState } from "react";

import { Messages, useAct, useLoad, when } from "@lugh/admin-ui";

import useAPI from "../hooks/useAPI";

const PAGE = 100;

// The audit log, a page at a time from the start, and its chain checked from end to end.
export default function Audit() {
	const api = useAPI();
	const [from, setFrom] = useState(1);
	const { value: page, error: loadError } = useLoad(() => api.audit(from, PAGE), [from]);
	const [verdict, setVerdict] = useState<string | undefined>(undefined);
	const { act, error } = useAct();

	const verify = () =>
		act(async () => {
			const checked = await api.verifyAudit();
			setVerdict(checked.intact ? `Intact: ${checked.entries} entries, each chained to the one before.` : `Broken: ${checked.problem}`);
		});

	return (
		<div className="page">
			<div className="page-header">
				<h2>Audit log</h2>
				<div className="actions">
					<button type="button" className="btn" onClick={verify}>
						Verify the chain
					</button>
				</div>
			</div>
			<Messages loadError={loadError} error={error} />
			{verdict && <p className={verdict.startsWith("Intact") ? "form-saved" : "form-error"}>{verdict}</p>}
			<section className="panel">
				<table className="data-table">
					<thead>
						<tr>
							<th>#</th>
							<th>When</th>
							<th>What</th>
							<th>Who</th>
							<th>About</th>
							<th>From</th>
							<th>Detail</th>
						</tr>
					</thead>
					<tbody>
						{page?.entries.map(entry => (
							<tr key={entry.sequence}>
								<td>{entry.sequence}</td>
								<td>{when(entry.time)}</td>
								<td>
									<code>{entry.action}</code>
								</td>
								<td>
									<code>{entry.actor}</code>
								</td>
								<td>
									<code>{entry.subject}</code>
								</td>
								<td>{entry.source}</td>
								<td className="muted">{entry.detail}</td>
							</tr>
						))}
					</tbody>
				</table>
				<div className="form-actions">
					<button type="button" className="btn" disabled={from <= 1} onClick={() => setFrom(Math.max(1, from - PAGE))}>
						Earlier
					</button>
					<button type="button" className="btn" disabled={!page?.next} onClick={() => page?.next && setFrom(page.next)}>
						Later
					</button>
				</div>
			</section>
		</div>
	);
}
