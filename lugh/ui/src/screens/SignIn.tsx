import { useState } from "react";

import { errorOf } from "../lib/api";
import { lughSignInUrl, type LughSignInConfig } from "../lib/lughSignIn";

// A service's sign-in: by its own name and password, by Lugh, or both, as the service offers them.
// Signing in by password is the service's own call (`onPassword`, which throws to refuse); by Lugh,
// the browser goes to Lugh and comes back to `lugh.redirectUri` (finishLughSignIn).
export function SignIn({
	service,
	onPassword,
	lugh,
	go = url => window.location.assign(url),
}: {
	service: string;
	onPassword?: (name: string, password: string) => Promise<void>;
	lugh?: LughSignInConfig;
	go?: (url: string) => void;
}) {
	const [name, setName] = useState("");
	const [password, setPassword] = useState("");
	const [error, setError] = useState("");
	const [busy, setBusy] = useState(false);

	const signIn = async (event: React.FormEvent) => {
		event.preventDefault();
		if (!onPassword) return;
		setBusy(true);
		setError("");
		try {
			await onPassword(name, password);
		} catch (e) {
			setError(errorOf(e));
			setPassword("");
		} finally {
			setBusy(false);
		}
	};

	const byLugh = async () => {
		if (!lugh) return;
		try {
			go(await lughSignInUrl(lugh));
		} catch (e) {
			setError(errorOf(e));
		}
	};

	return (
		<main className="sign-in">
			<section className="panel">
				<h2>Sign in to {service}</h2>
				{error && (
					<p className="form-error" role="alert">
						{error}
					</p>
				)}
				{onPassword && (
					<form onSubmit={signIn} className="form-grid">
						<label className="field wide">
							<span>Name</span>
							<input name="name" autoComplete="username" autoCapitalize="none" spellCheck={false} required value={name} onChange={e => setName(e.target.value)} />
						</label>
						<label className="field wide">
							<span>Password</span>
							<input name="password" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} />
						</label>
						<div className="form-actions">
							<button type="submit" className="btn primary" disabled={busy}>
								Sign in
							</button>
						</div>
					</form>
				)}
				{lugh && (
					<div className="form-actions">
						<button type="button" className={onPassword ? "btn" : "btn primary"} onClick={byLugh}>
							Sign in with Lugh
						</button>
					</div>
				)}
			</section>
		</main>
	);
}
