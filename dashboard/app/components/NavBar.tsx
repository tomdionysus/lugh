import { NavLink } from "react-router";

import { visible } from "../lib/sections";

import "./NavBar.css";

// The sections the person may read: everyone has their account, and each other section is shown
// to a person whose scopes let them read it.
export default function NavBar({ scopes }: { scopes: string[] }) {
	return (
		<nav className="navbar">
			{visible(scopes).map(section => (
				<NavLink key={section.to} to={section.to} end={section.to === "/"} className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}>
					{section.label}
				</NavLink>
			))}
		</nav>
	);
}
