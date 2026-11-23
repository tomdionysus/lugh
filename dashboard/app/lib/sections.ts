import { visible as visibleOf, type Section } from "@lugh/admin-ui";

// The dashboard's sections, in the order the bar shows them. `scope` is what a section's screen
// reads with; a section the person cannot read is not shown. "Account" is everyone's.
export const SECTIONS: Section[] = [
	{ to: "/", label: "Account" },
	{ to: "/users", label: "Users", scope: "lugh:directory.read" },
	{ to: "/groups", label: "Groups", scope: "lugh:directory.read" },
	{ to: "/policies", label: "Policies", scope: "lugh:directory.read" },
	{ to: "/apps", label: "Applications", scope: "lugh:directory.read" },
	{ to: "/keys", label: "Keys", scope: "lugh:directory.read" },
	{ to: "/audit", label: "Audit", scope: "lugh:audit.read" },
];

export function visible(scopes: string[]): Section[] {
	return visibleOf(SECTIONS, scopes);
}
