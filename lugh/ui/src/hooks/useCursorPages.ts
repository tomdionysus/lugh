import { useCallback, useEffect, useState } from "react";

import { errorOf } from "../lib/api";

// One page of a list the service hands out by an opaque cursor: the items, and the cursor of the
// page after, or none at the end.
export type Page<T> = { items: T[]; next: string | null };

// A list read a page at a time by the service's cursor (Lir's topics, Mimir's keys): the page shown,
// forward by the cursor the service gave, back by the cursors already seen. reload() reads the page
// shown again, after a change.
export function useCursorPages<T>(load: (cursor: string | undefined) => Promise<Page<T>>, deps: unknown[] = []) {
	// The cursor of each page so far, the first undefined; the last is the page shown.
	const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
	const [page, setPage] = useState<Page<T> | undefined>(undefined);
	const [error, setError] = useState<string | undefined>(undefined);
	const cursor = cursors[cursors.length - 1];

	const reload = useCallback(async () => {
		try {
			setPage(await load(cursor));
			setError(undefined);
		} catch (e) {
			setError(errorOf(e));
		}
	}, [cursor, ...deps]);

	useEffect(() => {
		reload();
	}, [reload]);

	// A change of what is listed (a filter the service applies, say) starts again from the first page.
	useEffect(() => setCursors([undefined]), deps);

	const next = () => {
		if (page?.next) setCursors([...cursors, page.next]);
	};
	const previous = () => {
		if (cursors.length > 1) setCursors(cursors.slice(0, -1));
	};

	return {
		items: page?.items,
		error,
		reload,
		next,
		previous,
		hasNext: Boolean(page?.next),
		hasPrevious: cursors.length > 1,
		// Which page is shown, from 1.
		number: cursors.length,
	};
}
