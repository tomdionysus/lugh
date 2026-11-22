import { MFA, PHR, PWD } from "./API";

// An acr as a person reads it. A time is @lugh/admin-ui's when().
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
