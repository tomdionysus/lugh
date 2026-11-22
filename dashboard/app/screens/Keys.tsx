import { Messages, useAct, useConfirm, useLoad, when } from "@lugh/admin-ui";

import useAPI from "../hooks/useAPI";

// The keys Lugh signs tokens with, never their private parts, and rotating one by hand. They also
// rotate by themselves after 90 days.
export default function Keys() {
	const api = useAPI();
	const { value: keys, error: loadError, reload } = useLoad(api.keys);
	const { act, error, message } = useAct(reload);
	const { ask, dialog } = useConfirm();

	const rotate = (algorithm: "ES256" | "EdDSA") =>
		ask(
			`Rotate the ${algorithm} key?`,
			<p>A new key is published now and signs from an hour on; the one it replaces stays published two hours more.</p>,
			"Rotate",
			() => act(() => api.rotateKey(algorithm), "Rotated"),
			false,
		);

	return (
		<div className="page">
			<div className="page-header">
				<h2>Signing keys</h2>
				<div className="actions">
					<button type="button" className="btn" onClick={() => rotate("ES256")}>
						Rotate ES256
					</button>
					<button type="button" className="btn" onClick={() => rotate("EdDSA")}>
						Rotate EdDSA
					</button>
				</div>
			</div>
			<Messages loadError={loadError} error={error} message={message} />
			<section className="panel">
				<table className="data-table">
					<thead>
						<tr>
							<th>Key</th>
							<th>Algorithm</th>
							<th>Made</th>
							<th>Signs from</th>
							<th>Retired</th>
						</tr>
					</thead>
					<tbody>
						{keys?.map(key => (
							<tr key={key.kid}>
								<td>
									<code>{key.kid}</code>
								</td>
								<td>{key.algorithm}</td>
								<td>{when(key.created_at)}</td>
								<td>{when(key.signing_from)}</td>
								<td>{when(key.retired_at)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</section>
			{dialog}
		</div>
	);
}
