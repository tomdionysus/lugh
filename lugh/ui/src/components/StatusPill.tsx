// How a state looks: one of the four verdicts the tokens carry. "unknown" is known to exist with
// nothing known about it, not a shade of the others.
export type Tone = "good" | "warn" | "bad" | "unknown";

// A state as a pill, its colour from the map the service gives (Louhi's container states, Mimir's
// replica roles): a state the map does not name is drawn plain.
export function StatusPill({ state, tones, label }: { state: string; tones: Record<string, Tone>; label?: string }) {
	const tone = tones[state];
	return (
		<span className={tone ? `pill ${tone}` : "pill"} data-state={state}>
			{label ?? state}
		</span>
	);
}
