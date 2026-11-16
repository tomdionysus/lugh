// WebAuthn ceremonies (W3C WebAuthn Level 3) from the options Lugh gives as JSON: the buffers it
// sends base64url-encoded are decoded for the browser, and what the authenticator returns is
// encoded again, as /api/v1/me/reauthenticate and /api/v1/me/factors/webauthn take it.

export function toBase64url(bytes: ArrayBuffer | Uint8Array): string {
	const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
	let text = "";
	for (const byte of view) text += String.fromCharCode(byte);
	return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(text: string): Uint8Array<ArrayBuffer> {
	const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
	const raw = atob(padded);
	const out = new Uint8Array(new ArrayBuffer(raw.length));
	for (let i = 0; i < raw.length; ++i) out[i] = raw.charCodeAt(i);
	return out;
}

type Descriptor = { type: "public-key"; id: string };

// Whether this browser can run a ceremony at all.
export function available(): boolean {
	return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

// A registration (create) with Lugh's options; what /api/v1/me/factors/webauthn takes.
export async function register(options: Record<string, unknown>, name: string) {
	const user = options.user as { id: string; name: string; displayName: string };
	const credential = (await navigator.credentials.create({
		publicKey: {
			challenge: fromBase64url(options.challenge as string),
			rp: options.rp as PublicKeyCredentialRpEntity,
			user: { id: fromBase64url(user.id), name: user.name, displayName: user.displayName },
			pubKeyCredParams: options.pubKeyCredParams as PublicKeyCredentialParameters[],
			authenticatorSelection: options.authenticatorSelection as AuthenticatorSelectionCriteria,
			attestation: options.attestation as AttestationConveyancePreference,
			timeout: options.timeout as number,
			excludeCredentials: ((options.excludeCredentials as Descriptor[]) ?? []).map(one => ({ type: one.type, id: fromBase64url(one.id) })),
		},
	})) as PublicKeyCredential | null;
	if (!credential) throw new Error("No key was made");
	const response = credential.response as AuthenticatorAttestationResponse;
	return {
		name,
		challenge: options.challenge as string,
		client_data: toBase64url(response.clientDataJSON),
		attestation_object: toBase64url(response.attestationObject),
	};
}

// An assertion (get) with Lugh's options; what /api/v1/me/reauthenticate takes as `webauthn`.
export async function assert(options: Record<string, unknown>) {
	const credential = (await navigator.credentials.get({
		publicKey: {
			challenge: fromBase64url(options.challenge as string),
			rpId: options.rpId as string,
			userVerification: options.userVerification as UserVerificationRequirement,
			timeout: options.timeout as number,
			allowCredentials: ((options.allowCredentials as Descriptor[]) ?? []).map(one => ({ type: one.type, id: fromBase64url(one.id) })),
		},
	})) as PublicKeyCredential | null;
	if (!credential) throw new Error("No key answered");
	const response = credential.response as AuthenticatorAssertionResponse;
	return {
		challenge: options.challenge as string,
		id: toBase64url(credential.rawId),
		client_data: toBase64url(response.clientDataJSON),
		authenticator_data: toBase64url(response.authenticatorData),
		signature: toBase64url(response.signature),
	};
}
