import { describe, expect, it } from "vitest";

import { MFA, PHR } from "./API";
import { assurance } from "./format";
import { visible } from "./sections";
import { fromBase64url, toBase64url } from "./webauthn";

describe("base64url", () => {
	it("round-trips every byte, without padding", () => {
		const bytes = new Uint8Array(256).map((_, i) => i);
		const text = toBase64url(bytes);
		expect(text).not.toMatch(/[+/=]/);
		expect(Array.from(fromBase64url(text))).toEqual(Array.from(bytes));
		expect(toBase64url(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
		expect(Array.from(fromBase64url("-_8"))).toEqual([0xfb, 0xff]);
	});
});

describe("sections", () => {
	it("shows the account to everyone and a section only to who may read it", () => {
		expect(visible([]).map(one => one.label)).toEqual(["Account"]);
		expect(visible(["lugh:directory.read"]).map(one => one.label)).toEqual(["Account", "Users", "Groups", "Policies", "Applications", "Keys"]);
		expect(visible(["lugh:audit.read"]).map(one => one.label)).toEqual(["Account", "Audit"]);
	});
});

describe("assurance", () => {
	it("names the levels as a person reads them", () => {
		expect(assurance(MFA)).toBe("Two factors");
		expect(assurance(PHR)).toBe("Passkey");
		expect(assurance("urn:other")).toBe("urn:other");
	});
});
