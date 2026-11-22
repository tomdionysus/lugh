import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Confirm } from "./Confirm";
import { Messages } from "./Messages";
import { NavBar } from "./NavBar";

afterEach(cleanup);

describe("Confirm", () => {
	it("does the change only when confirmed, and cancels on Escape", () => {
		const confirmed = vi.fn();
		const cancelled = vi.fn();
		render(
			<Confirm title="Remove?" action="Remove" danger onConfirm={confirmed} onCancel={cancelled}>
				<p>It goes for good.</p>
			</Confirm>,
		);
		expect(screen.getByRole("dialog", { name: "Remove?" })).toBeTruthy();
		fireEvent.keyDown(window, { key: "Escape" });
		expect(cancelled).toHaveBeenCalledTimes(1);
		expect(confirmed).not.toHaveBeenCalled();
		fireEvent.click(screen.getByText("Remove"));
		expect(confirmed).toHaveBeenCalledTimes(1);
	});
});

describe("NavBar", () => {
	const sections = [
		{ to: "/", label: "Status" },
		{ to: "/topics", label: "Topics", scope: "lir:read" },
		{ to: "/audit", label: "Audit", scope: "lir:audit" },
	];

	it("shows the sections without a scope, and only those others the person may read", () => {
		render(
			<MemoryRouter>
				<NavBar sections={sections} scopes={["lir:audit"]} />
			</MemoryRouter>,
		);
		expect(screen.getByText("Status")).toBeTruthy();
		expect(screen.getByText("Audit")).toBeTruthy();
		expect(screen.queryByText("Topics")).toBeNull();
	});
});

describe("Messages", () => {
	it("says the error as an alert, and what was done otherwise", () => {
		render(<Messages error="the name is taken" message="" loadError="" />);
		expect(screen.getByRole("alert").textContent).toBe("the name is taken");
		cleanup();
		render(<Messages message="Saved" />);
		expect(screen.queryByRole("alert")).toBeNull();
		expect(screen.getByText("Saved")).toBeTruthy();
	});
});
