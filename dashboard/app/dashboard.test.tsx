import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import AdminLayout from "./layouts/AdminLayout";
import { MFA } from "./lib/API";
import Account from "./screens/Account";
import Audit from "./screens/Audit";
import GroupDetail from "./screens/GroupDetail";
import Groups from "./screens/Groups";
import UserDetail from "./screens/UserDetail";
import Users from "./screens/Users";
import { FakeLugh } from "./test/fakeLugh";

// The dashboard's story (P7), as the end-to-end tests told it on a real lugh-node, now in Vitest's
// browser mode against Lugh's API in memory (the maintainer, 2026-11-22): root at phr administers,
// adds a person and their enrolment link, makes a group and puts them in it, sees their own passkey
// and the audit log, and signs out; below phr, the step-up is offered. The sign-in pages themselves
// are Lugh's, tested by the process tests (node_process_*).

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function dashboard(lugh: FakeLugh, at = "/") {
	vi.stubGlobal("fetch", lugh.fetch);
	const router = createMemoryRouter(
		[
			{
				element: <AdminLayout />,
				children: [
					{ index: true, element: <Account /> },
					{ path: "users", element: <Users /> },
					{ path: "users/:id", element: <UserDetail /> },
					{ path: "groups", element: <Groups /> },
					{ path: "groups/:id", element: <GroupDetail /> },
					{ path: "audit", element: <Audit /> },
				],
			},
		],
		{ initialEntries: [at] },
	);
	render(<RouterProvider router={router} />);
	return router;
}

const nav = (label: string) => screen.getAllByRole("link", { name: label }).find(link => link.classList.contains("nav-item"))!;

describe("The dashboard at phr", () => {
	it("shows root signed in with a passkey, the sections they administer, and no step-up", async () => {
		dashboard(new FakeLugh());
		expect((await screen.findByTitle("How you signed in")).textContent).toBe("Passkey");
		expect(nav("Users")).toBeTruthy();
		expect(nav("Audit")).toBeTruthy();
		expect(screen.queryByText(/Administering needs a sign-in/)).toBeNull();
	});

	it("adds a person and makes their enrolment link", async () => {
		const lugh = new FakeLugh();
		const router = dashboard(lugh, "/users");
		fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "alice" } });
		fireEvent.change(screen.getByLabelText("Address"), { target: { value: "alice@example.test" } });
		fireEvent.click(screen.getByRole("button", { name: "Add user" }));
		await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/users\/.+/));
		expect(await screen.findByText("Not enrolled")).toBeTruthy();
		// The factors panel, which holds the link, comes once the user's factors are read.
		fireEvent.click(await screen.findByRole("button", { name: "Make an enrolment link" }));
		expect((await screen.findByText(/\/signin\/enrol\/l1nk/)).classList.contains("secret-once")).toBe(true);
		expect(lugh.asked.filter(one => one.startsWith("POST"))).toEqual(["POST /api/v1/users", `POST /api/v1/users/${lugh.users[1].id}/enrolment`]);
	});

	it("makes a group and puts alice in it", async () => {
		const lugh = new FakeLugh();
		await lugh.fetch("/api/v1/users", { method: "POST", body: JSON.stringify({ name: "alice", email: "alice@example.test" }) });
		dashboard(lugh, "/groups");
		fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "operators" } });
		fireEvent.click(screen.getByRole("button", { name: "Add group" }));
		expect(await screen.findByRole("heading", { name: "operators" })).toBeTruthy();
		const add = await screen.findByLabelText("User to add");
		await waitFor(() => expect(add.querySelectorAll("option").length).toBeGreaterThan(1));
		const alice = Array.from(add.querySelectorAll("option")).find(option => option.textContent === "alice")!;
		fireEvent.change(add, { target: { value: alice.value } });
		fireEvent.click(screen.getByRole("button", { name: "Add" }));
		expect(await screen.findByRole("link", { name: "alice" })).toBeTruthy();
	});

	it("shows root's passkey on their account, and the audit log what was done, its chain intact", async () => {
		const lugh = new FakeLugh();
		await lugh.fetch("/api/v1/users", { method: "POST", body: JSON.stringify({ name: "alice", email: "alice@example.test" }) });
		dashboard(lugh);
		expect((await screen.findAllByRole("cell", { name: "Passkey" })).length).toBeGreaterThan(0);
		fireEvent.click(nav("Audit"));
		expect((await screen.findAllByText("user.create")).length).toBeGreaterThan(0);
		fireEvent.click(screen.getByRole("button", { name: "Verify the chain" }));
		expect(await screen.findByText(/^Intact/)).toBeTruthy();
	});

	it("signs out by posting Lugh's sign-out form with the session's CSRF token", async () => {
		dashboard(new FakeLugh());
		const form = (await screen.findByRole("button", { name: "Sign out" })).closest("form")!;
		expect(form.getAttribute("action")).toBe("/signout");
		expect(form.getAttribute("method")).toBe("post");
		expect((form.querySelector("input[name=csrf]") as HTMLInputElement).value).toBe("csrf-t0ken");
	});
});

describe("The dashboard below phr", () => {
	it("offers the passkey step-up to someone who administers", async () => {
		dashboard(new FakeLugh(MFA));
		expect((await screen.findByTitle("How you signed in")).textContent).toBe("Two factors");
		expect(screen.getByText(/Administering needs a sign-in/)).toBeTruthy();
		expect(screen.getByRole("button", { name: "Sign in with a passkey" })).toBeTruthy();
	});
});
