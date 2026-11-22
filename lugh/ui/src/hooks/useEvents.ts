import { useEffect, useRef, useState } from "react";

export type EventsOptions = {
	// The SSE event names to listen for; none: unnamed messages ("message").
	events?: string[];
	// The first wait after a drop, doubled at each drop after, to at most `longest`; a connection that
	// opens starts it over.
	shortest?: number;
	longest?: number;
	// The EventSource to use: the browser's by default, a test's own.
	source?: typeof EventSource;
};

// A service's server-sent events (Lir's deliveries, Louhi's container states): each event's data, as
// JSON, to `onEvent`, and whether the stream is up. A dropped stream is opened again after a back-off
// with jitter, never given up; the browser's own retry is not relied on, as it does not back off.
export function useEvents<T = unknown>(url: string | undefined, onEvent: (data: T, event: string) => void, options: EventsOptions = {}) {
	const { events = ["message"], shortest = 1000, longest = 30000, source = typeof EventSource === "undefined" ? undefined : EventSource } = options;
	const [connected, setConnected] = useState(false);
	const [error, setError] = useState<string | undefined>(undefined);
	// The newest handler, so a render that makes a new one does not reopen the stream.
	const handler = useRef(onEvent);
	handler.current = onEvent;

	useEffect(() => {
		if (!url || !source) return;
		let stream: EventSource | undefined;
		let timer: ReturnType<typeof setTimeout> | undefined;
		let wait = shortest;
		let closed = false;

		const open = () => {
			stream = new source(url);
			stream.onopen = () => {
				wait = shortest;
				setConnected(true);
				setError(undefined);
			};
			for (const name of events) {
				stream.addEventListener(name, message => {
					const data = (message as MessageEvent).data;
					try {
						handler.current(JSON.parse(data) as T, name);
					} catch {
						setError(`an event that is not JSON: ${String(data).slice(0, 80)}`);
					}
				});
			}
			stream.onerror = () => {
				stream?.close();
				setConnected(false);
				if (closed) return;
				// Half the back-off, plus jitter over the other half, so many UIs a restart dropped do not
				// all come back at once.
				const delay = Math.round(wait / 2 + Math.random() * (wait / 2));
				wait = Math.min(wait * 2, longest);
				timer = setTimeout(open, delay);
			};
		};
		open();

		return () => {
			closed = true;
			if (timer) clearTimeout(timer);
			stream?.close();
			setConnected(false);
		};
	}, [url, source, shortest, longest, events.join(" ")]);

	return { connected, error };
}
