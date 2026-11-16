import { MFA, PHR, PWD } from "./API";

// An RFC 3339 time as the person's own clock shows it; empty for none.
export function when(time: string | null | undefined): string {
	if (!time) return "";
	const parsed = new Date(time);
	return Number.isNaN(parsed.getTime()) ? time : parsed.toLocaleString();
}

// An acr as a person reads it.
export function assurance(acr: string): string {
	switch (acr) {
		case PWD:
			return "Password";
		case MFA:
			return "Two factors";
		case PHR:
			return "Passkey";
		default:
			return acr;
	}
}
