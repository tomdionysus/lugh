import type { ReactNode } from "react";
import { Link } from "react-router";

import { NavBar } from "../components/NavBar";
import type { Section } from "../lib/sections";

import "./AdminShell.css";

export type AdminShellProps = {
	// The wordmark, linking home.
	brand: string;
	home?: string;
	sections: Section[];
	scopes: string[];
	// Who is signed in, as a person reads it, and their full name for the tooltip.
	account: { name: string; title?: string };
	// How they are signed in: a label, live (enough) or stale (below what the UI wants), and why.
	status?: { label: string; live: boolean; title?: string };
	// Sign out: a form posted to the service (its action and hidden fields, a CSRF token say), or a
	// callback for a UI that signs out itself.
	signOut?: { action: string; fields?: Record<string, string> } | { onSignOut: () => void };
	// Above every screen: what the person should know, a step-up offer say.
	notice?: ReactNode;
	footer?: ReactNode;
	children: ReactNode;
};

// The chrome around every screen: the wordmark, the sections the person may read, who is signed
// in and how, and the way out. The T.O.M.S layout, one for every service of the stack.
export function AdminShell({ brand, home = "/", sections, scopes, account, status, signOut, notice, footer, children }: AdminShellProps) {
	return (
		<div className="admin">
			<header className="topbar">
				<Link className="brand" to={home}>
					<h1 className="brand-name">{brand}</h1>
				</Link>
				<NavBar sections={sections} scopes={scopes} />
				<div className="topbar-right">
					{status && (
						<span className={`status ${status.live ? "live" : "stale"}`} title={status.title ?? "How you signed in"}>
							{status.label}
						</span>
					)}
					<div className="account">
						<span className="account-name" title={account.title ?? account.name}>
							{account.name}
						</span>
						{signOut && "action" in signOut && (
							<form method="post" action={signOut.action}>
								{Object.entries(signOut.fields ?? {}).map(([name, value]) => (
									<input key={name} type="hidden" name={name} value={value} />
								))}
								<button type="submit" className="account-signout">
									Sign out
								</button>
							</form>
						)}
						{signOut && "onSignOut" in signOut && (
							<button type="button" className="account-signout" onClick={signOut.onSignOut}>
								Sign out
							</button>
						)}
					</div>
				</div>
			</header>

			<main className="screen">
				{notice}
				{children}
			</main>

			<footer className="bottombar">
				<span className="version">{footer ?? brand}</span>
				<span className="host">{typeof window === "undefined" ? "" : window.location.host}</span>
			</footer>
		</div>
	);
}
