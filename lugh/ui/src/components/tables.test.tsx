import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCursorPages, type Page } from "../hooks/useCursorPages";
import { DataTable, type Column } from "./DataTable";
import { DetailPanel } from "./DetailPanel";
import { StatusPill } from "./StatusPill";

afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
});

type Topic = { name: string; subscribers: number };
const topics: Topic[] = [
	{ name: "lir/b", subscribers: 3 },
	{ name: "lir/a", subscribers: 10 },
	{ name: "mimir/c", subscribers: 1 },
];
const columns: Column<Topic>[] = [
	{ key: "name", label: "Topic", sortBy: row => row.name },
	{ key: "subscribers", label: "Subscribers", sortBy: row => row.subscribers },
];
const names = () => screen.getAllByRole("row").slice(1).map(row => row.querySelector("td")!.textContent);

describe("DataTable", () => {
	it("sorts by a column, ascending then descending", () => {
		render(<DataTable columns={columns} rows={topics} rowKey={row => row.name} />);
		expect(names()).toEqual(["lir/b", "lir/a", "mimir/c"]);
		fireEvent.click(screen.getByRole("button", { name: "Subscribers" }));
		expect(names()).toEqual(["mimir/c", "lir/b", "lir/a"]);
		fireEvent.click(screen.getByRole("button", { name: "Subscribers" }));
		expect(names()).toEqual(["lir/a", "lir/b", "mimir/c"]);
		expect(screen.getByRole("columnheader", { name: "Subscribers" }).getAttribute("aria-sort")).toBe("descending");
	});

	it("filters by what the person types, and says so when nothing is left", () => {
		render(<DataTable columns={columns} rows={topics} rowKey={row => row.name} filterText={row => row.name} label="topics" empty="No topics" />);
		fireEvent.change(screen.getByLabelText("Find in topics"), { target: { value: "LIR/" } });
		expect(names()).toEqual(["lir/b", "lir/a"]);
		fireEvent.change(screen.getByLabelText("Find in topics"), { target: { value: "kvasir" } });
		expect(screen.getByText("No topics")).toBeTruthy();
	});

	it("opens a row", () => {
		const opened = vi.fn();
		render(<DataTable columns={columns} rows={topics} rowKey={row => row.name} onRowClick={opened} />);
		fireEvent.click(screen.getByText("lir/a"));
		expect(opened).toHaveBeenCalledWith(topics[1]);
	});
});

// A list the service pages by an opaque cursor, with the table it fills.
function Topics({ load }: { load: (cursor: string | undefined) => Promise<Page<Topic>> }) {
	const pages = useCursorPages(load);
	return <DataTable columns={columns} rows={pages.items} rowKey={row => row.name} paging={pages} />;
}

describe("useCursorPages", () => {
	it("goes forward by the service's cursor and back by the cursors seen, and has no next at the end", async () => {
		const served: Record<string, Page<Topic>> = {
			first: { items: [topics[0]], next: "c2" },
			c2: { items: [topics[1]], next: "c3" },
			c3: { items: [topics[2]], next: null },
		};
		const load = vi.fn(async (cursor: string | undefined) => served[cursor ?? "first"]);
		render(<Topics load={load} />);
		await waitFor(() => expect(names()).toEqual(["lir/b"]));
		expect((screen.getByRole("button", { name: "Previous" }) as HTMLButtonElement).disabled).toBe(true);

		await act(async () => fireEvent.click(screen.getByRole("button", { name: "Next" })));
		await waitFor(() => expect(names()).toEqual(["lir/a"]));
		await act(async () => fireEvent.click(screen.getByRole("button", { name: "Next" })));
		await waitFor(() => expect(names()).toEqual(["mimir/c"]));
		expect(screen.getByText("Page 3")).toBeTruthy();
		expect((screen.getByRole("button", { name: "Next" }) as HTMLButtonElement).disabled).toBe(true);

		await act(async () => fireEvent.click(screen.getByRole("button", { name: "Previous" })));
		await waitFor(() => expect(names()).toEqual(["lir/a"]));
		expect(load).toHaveBeenLastCalledWith("c2");
	});
});

describe("DetailPanel", () => {
	it("labels each field, and copies what is worth copying", async () => {
		const written = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
		render(<DetailPanel title="Container" details={[{ label: "Image", value: "debian:trixie" }, { label: "Id", value: "c0ffee", copy: "c0ffee", mono: true }]} />);
		expect(screen.getByText("Image")).toBeTruthy();
		expect(screen.queryByRole("button", { name: "Copy Image" })).toBeNull();
		await act(async () => fireEvent.click(screen.getByRole("button", { name: "Copy Id" })));
		expect(written).toHaveBeenCalledWith("c0ffee");
		expect(screen.getByRole("button", { name: "Copy Id" }).textContent).toBe("Copied");
	});
});

describe("StatusPill", () => {
	it("takes its colour from the service's map, and is plain for a state the map does not name", () => {
		const tones = { running: "good", restarting: "warn", exited: "bad" } as const;
		render(
			<>
				<StatusPill state="running" tones={tones} />
				<StatusPill state="paused" tones={tones} label="Paused" />
			</>,
		);
		expect(screen.getByText("running").className).toBe("pill good");
		expect(screen.getByText("Paused").className).toBe("pill");
	});
});
