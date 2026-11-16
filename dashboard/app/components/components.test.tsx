import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import Confirm from "./Confirm";
import NavBar from "./NavBar";
import QrCode from "./QrCode";

afterEach(cleanup);

describe("QrCode", () => {
	it("draws one square per dark module, inside the quiet zone", () => {
		const { container } = render(<QrCode size={2} modules="1001" label="code" />);
		const svg = container.querySelector("svg")!;
		expect(svg.getAttribute("viewBox")).toBe("0 0 10 10");
		const path = container.querySelector("path")!.getAttribute("d")!;
		expect(path).toBe("M4 4h1v1h-1zM5 5h1v1h-1z");
		expect(screen.getByRole("img", { name: "code" })).toBeTruthy();
	});
});

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
	it("shows only the sections the person may read", () => {
		render(
			<MemoryRouter>
				<NavBar scopes={["lugh:audit.read"]} />
			</MemoryRouter>,
		);
		expect(screen.getByText("Account")).toBeTruthy();
		expect(screen.getByText("Audit")).toBeTruthy();
		expect(screen.queryByText("Users")).toBeNull();
	});
});
