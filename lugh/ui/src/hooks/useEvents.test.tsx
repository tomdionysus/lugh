import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useEvents } from "./useEvents";

// An EventSource a test drives: each one made is kept, and the test opens it, sends on it or drops it.
class FakeSource {
	static made: FakeSource[] = [];
	onopen: (() => void) | null = null;
	onerror: (() => void) | null = null;
	closed = false;
	private listeners = new Map<string, ((event: MessageEvent) => void)[]>();
	constructor(public url: string) {
		FakeSource.made.push(this);
	}
	addEventListener(name: string, listener: (event: MessageEvent) => void) {
		this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]);
	}
	close() {
		this.closed = true;
	}
	send(name: string, data: string) {
		for (const listener of this.listeners.get(name) ?? []) listener(new MessageEvent(name, { data }));
	}
}

const source = FakeSource as unknown as typeof EventSource;
const latest = () => FakeSource.made[FakeSource.made.length - 1];

function Deliveries({ seen }: { seen: unknown[] }) {
	const { connected, error } = useEvents<{ topic: string }>("/api/deliveries", data => seen.push(data), { events: ["delivery"], shortest: 1000, longest: 4000, source });
	return (
		<p>
			{connected ? "up" : "down"} {error}
		</p>
	);
}

beforeEach(() => {
	FakeSource.made = [];
	vi.useFakeTimers();
	vi.spyOn(Math, "random").mockReturnValue(1);
});

afterEach(() => {
	cleanup();
	vi.useRealTimers();
	vi.restoreAllMocks();
});

describe("useEvents", () => {
	it("hands each event's JSON on, and says when the stream is up", () => {
		const seen: unknown[] = [];
		render(<Deliveries seen={seen} />);
		expect(latest().url).toBe("/api/deliveries");
		act(() => latest().onopen!());
		expect(screen.getByText(/^up/)).toBeTruthy();
		act(() => latest().send("delivery", '{"topic":"lir/a"}'));
		expect(seen).toEqual([{ topic: "lir/a" }]);
		act(() => latest().send("delivery", "not json"));
		expect(screen.getByText(/an event that is not JSON/)).toBeTruthy();
	});

	it("opens a dropped stream again after a back-off that doubles to its longest, and starts over once open", () => {
		render(<Deliveries seen={[]} />);
		const waits: number[] = [];
		for (let drop = 0; drop < 4; drop++) {
			const dropped = latest();
			act(() => dropped.onerror!());
			expect(dropped.closed).toBe(true);
			const before = FakeSource.made.length;
			let waited = 0;
			while (FakeSource.made.length === before) {
				act(() => vi.advanceTimersByTime(100));
				waited += 100;
			}
			waits.push(waited);
		}
		// With the jitter at its top: 1 s, 2 s, then 4 s at most.
		expect(waits).toEqual([1000, 2000, 4000, 4000]);
		act(() => latest().onopen!());
		act(() => latest().onerror!());
		const before = FakeSource.made.length;
		act(() => vi.advanceTimersByTime(1000));
		expect(FakeSource.made.length).toBe(before + 1);
	});

	it("closes the stream and opens no other once the screen is gone", () => {
		const { unmount } = render(<Deliveries seen={[]} />);
		const stream = latest();
		act(() => stream.onerror!());
		unmount();
		act(() => vi.advanceTimersByTime(60000));
		expect(FakeSource.made).toHaveLength(1);
	});
});
