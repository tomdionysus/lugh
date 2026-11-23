// An RFC 3339 time as the person's own clock shows it; empty for none, and the text itself for
// what is not a time.
export function when(time: string | null | undefined): string {
	if (!time) return "";
	const parsed = new Date(time);
	return Number.isNaN(parsed.getTime()) ? time : parsed.toLocaleString();
}
