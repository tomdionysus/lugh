import { NavLink } from "react-router";

import { visible, type Section } from "../lib/sections";

import "./NavBar.css";

// The sections the person may read: those without a scope, and each other one a person whose
// scopes let them read it.
export function NavBar({ sections, scopes }: { sections: Section[]; scopes: string[] }) {
	return (
		<nav className="navbar">
			{visible(sections, scopes).map(section => (
				<NavLink key={section.to} to={section.to} end={section.to === "/"} className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}>
					{section.label}
				</NavLink>
			))}
		</nav>
	);
}
