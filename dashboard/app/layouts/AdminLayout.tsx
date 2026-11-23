import { useEffect, useMemo, useState } from "react";
import { Outlet, useOutletContext } from "react-router";

import { AdminShell, ApiContext, errorOf } from "@lugh/admin-ui";

import { API, PHR, signInUrl, type Me } from "../lib/API";
import { assurance } from "../lib/format";
import { SECTIONS, visible } from "../lib/sections";

export type Signed = { me: Me; reload: () => Promise<void> };

// What every screen is given: the person signed in, and a way to read them again.
export function useSigned() {
	return useOutletContext<Signed>();
}

// Where the browser goes when it must sign in: Lugh's own pages, which come back here.
function signIn(stepUp = false) {
	window.location.assign(signInUrl(stepUp));
}

// @lugh/admin-ui's shell around every screen, with what is Lugh's: nobody signed in is sent to
// Lugh's sign-in, which comes back here, and administering needs a passkey sign-in (phr): below it,
// the screens that would administer say so and offer the step-up.
export default function AdminLayout() {
	const api = useMemo(() => new API(), []);
	const [me, setMe] = useState<Me | undefined>(undefined);
	const [error, setError] = useState("");
	const [refused, setRefused] = useState(false);

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
	const notice =
		administers && belowPhr ? (
			<div className={`notice ${refused ? "warn" : ""}`} role={refused ? "alert" : undefined}>
				<span>Administering needs a sign-in with a passkey or security key. Your own account is open to you as you are.</span>
				<button type="button" className="btn primary" onClick={() => signIn(true)}>
					Sign in with a passkey
				</button>
			</div>
		) : null;

	return (
		<ApiContext.Provider value={api}>
			<AdminShell
				brand="Lugh"
				sections={SECTIONS}
				scopes={me.scopes}
				account={{ name: me.user.display_name || me.user.name, title: me.user.name }}
				status={{ label: assurance(acr), live: !belowPhr }}
				signOut={{ action: "/signout", fields: { csrf: me.session?.csrf_token ?? "" } }}
				notice={notice}
			>
				<Outlet context={{ me, reload } satisfies Signed} />
			</AdminShell>
		</ApiContext.Provider>
	);
}
