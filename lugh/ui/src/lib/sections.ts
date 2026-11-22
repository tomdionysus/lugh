// A UI's sections, in the order the bar shows them. `scope` is what a section's screen reads with; a
// section the person cannot read is not shown. A section without one is everyone's.
export type Section = { to: string; label: string; scope?: string };

export function visible(sections: Section[], scopes: string[]): Section[] {
	return sections.filter(section => !section.scope || scopes.includes(section.scope));
}
