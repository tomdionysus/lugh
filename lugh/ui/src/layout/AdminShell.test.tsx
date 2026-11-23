import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AdminShell } from "./AdminShell";

afterEach(cleanup);

const sections = [
	{ to: "/", label: "Status" },
	{ to: "/keys", label: "Keys", scope: "mimir:admin" },
];

describe("AdminShell", () => {
	it("shows the brand, the sections the person may read, who is signed in and how", () => {
		render(
			<MemoryRouter>
				<AdminShell brand="Mimir" sections={sections} scopes={[]} account={{ name: "Alice", title: "alice" }} status={{ label: "Two factors", live: false }}>
					<p>the screen</p>
				</AdminShell>
			</MemoryRouter>,
		);
		expect(screen.getByRole("heading", { name: "Mimir" })).toBeTruthy();
		expect(screen.getByText("Status")).toBeTruthy();
		expect(screen.queryByText("Keys")).toBeNull();
		expect(screen.getByTitle("alice").textContent).toBe("Alice");
		expect(screen.getByText("Two factors").className).toContain("stale");
		expect(screen.getByText("the screen")).toBeTruthy();
	});

	it("signs out by posting the service's form with its fields, or by the UI's own callback", () => {
		const { container } = render(
			<MemoryRouter>
				<AdminShell brand="Lugh" sections={sections} scopes={[]} account={{ name: "root" }} signOut={{ action: "/signout", fields: { csrf: "t0ken" } }}>
					<p />
				</AdminShell>
			</MemoryRouter>,
		);
		const form = container.querySelector("form")!;
		expect(form.getAttribute("action")).toBe("/signout");
		expect(form.getAttribute("method")).toBe("post");
		expect((form.querySelector("input[name=csrf]") as HTMLInputElement).value).toBe("t0ken");
		cleanup();

		const signedOut = vi.fn();
		render(
			<MemoryRouter>
				<AdminShell brand="Kvasir" sections={sections} scopes={[]} account={{ name: "root" }} signOut={{ onSignOut: signedOut }}>
					<p />
				</AdminShell>
			</MemoryRouter>,
		);
		fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
		expect(signedOut).toHaveBeenCalledTimes(1);
	});
});
