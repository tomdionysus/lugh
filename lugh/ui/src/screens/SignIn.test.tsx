import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../lib/api";
import { SignIn } from "./SignIn";

afterEach(() => {
	cleanup();
	sessionStorage.clear();
});

const lugh = { authorizationEndpoint: "https://lugh.example/oauth2/authorize", clientId: "louhi-admin", redirectUri: "https://louhi.example/admin/signed-in" };

describe("SignIn", () => {
	it("signs in by the service's name and password, and says a refusal, the password cleared", async () => {
		const onPassword = vi.fn().mockRejectedValueOnce(new ApiError(401, "refused", "that name and password do not match")).mockResolvedValueOnce(undefined);
		render(<SignIn service="Louhi" onPassword={onPassword} />);
		expect(screen.getByRole("heading", { name: "Sign in to Louhi" })).toBeTruthy();
		fireEvent.change(screen.getByLabelText("Name"), { target: { value: "alice" } });
		fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong" } });
		await act(async () => fireEvent.click(screen.getByRole("button", { name: "Sign in" })));
		expect(onPassword).toHaveBeenCalledWith("alice", "wrong");
		expect(screen.getByRole("alert").textContent).toBe("that name and password do not match");
		expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
		expect(screen.queryByRole("button", { name: "Sign in with Lugh" })).toBeNull();
	});

	it("signs in by Lugh: the browser goes to Lugh's authorization endpoint with a PKCE challenge", async () => {
		const go = vi.fn();
		render(<SignIn service="Kvasir" lugh={lugh} go={go} />);
		expect(screen.queryByLabelText("Password")).toBeNull();
		await act(async () => fireEvent.click(screen.getByRole("button", { name: "Sign in with Lugh" })));
		expect(go).toHaveBeenCalledTimes(1);
		const url = new URL(go.mock.calls[0][0]);
		expect(url.origin + url.pathname).toBe(lugh.authorizationEndpoint);
		expect(url.searchParams.get("client_id")).toBe("louhi-admin");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		expect(sessionStorage.getItem("lugh-sign-in")).not.toBeNull();
	});
});
