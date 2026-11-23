import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import QrCode from "./QrCode";

// Lugh's own components; the shared ones are tested in @lugh/admin-ui (lugh/ui).
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
