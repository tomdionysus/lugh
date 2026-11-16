import { useEffect, useMemo, useRef, useState } from "react";
import { Link, Outlet, useOutletContext } from "react-router";

import NavBar from "../components/NavBar";
import { ApiContext } from "../hooks/useAPI";
import { API, errorOf, PHR, signInUrl, type Me } from "../lib/API";
import { assurance } from "../lib/format";
import { visible } from "../lib/sections";

import "./AdminLayout.css";

export type Signed = { me: Me; reload: () => Promise<void> };

// What every screen is given: the person signed in, and a way to read them again.
export function useSigned() {
	return useOutletContext<Signed>();
}

// Where the browser goes when it must sign in: Lugh's own pages, which come back here.
function signIn(stepUp = false) {
	window.location.assign(signInUrl(stepUp));
}

// The chrome around every screen: the wordmark, the sections the person may read, who is signed
// in and how, and the way out. Nobody signed in is sent to Lugh's sign-in, which comes back here.
// Administering needs a passkey sign-in (phr): below it, the screens that would administer say so
// and offer the step-up.
export default function AdminLayout() {
	const api = useMemo(() => new API(), []);
	const [me, setMe] = useState<Me | undefined>(undefined);
	const [error, setError] = useState("");
	const [refused, setRefused] = useState(false);
	const signOut = useRef<HTMLFormElement>(null);

	const reload = async () => {
		try {
			setMe(await api.me());
			setError("");
		} catch (e) {
			setError(errorOf(e));
		}
	};

	useEffect(() => {
		api.onUnauthorised = () => signIn();
		api.onStepUp = () => setRefused(true);
		reload();
	}, [api]);

	if (me === undefined) {
		return (
			<div className="hydrate-fallback">
				<p>{error || "Loading"}</p>
			</div>
		);
	}

	const acr = me.session?.acr ?? "";
	const administers = visible(me.scopes).length > 1;
	const belowPhr = acr !== PHR;

	return (
		<ApiContext.Provider value={api}>
			<div className="admin">
				<header className="topbar">
					<Link className="brand" to="/">
						<h1 className="brand-name">Lugh</h1>
					</Link>
					<NavBar scopes={me.scopes} />
					<div className="topbar-right">
						<span className={`status ${belowPhr ? "stale" : "live"}`} title="How you signed in">
							{assurance(acr)}
						</span>
						<div className="account">
							<span className="account-name" title={me.user.name}>
								{me.user.display_name || me.user.name}
							</span>
							<form ref={signOut} method="post" action="/signout">
								<input type="hidden" name="csrf" value={me.session?.csrf_token ?? ""} />
								<button type="submit" className="account-signout">
									Sign out
								</button>
							</form>
						</div>
					</div>
				</header>

				<main className="screen">
					{administers && belowPhr && (
						<div className={`notice ${refused ? "warn" : ""}`} role={refused ? "alert" : undefined}>
							<span>Administering needs a sign-in with a passkey or security key. Your own account is open to you as you are.</span>
							<button type="button" className="btn primary" onClick={() => signIn(true)}>
								Sign in with a passkey
							</button>
						</div>
					)}
					<Outlet context={{ me, reload } satisfies Signed} />
				</main>

				<footer className="bottombar">
					<span className="version">Lugh</span>
					<span className="host">{typeof window === "undefined" ? "" : window.location.host}</span>
				</footer>
			</div>
		</ApiContext.Provider>
	);
}
