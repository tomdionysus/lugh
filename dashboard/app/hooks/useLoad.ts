import { useCallback, useEffect, useState } from "react";

import { errorOf } from "../lib/API";

// One thing read from Lugh: the value once it arrives, the error if it did not, and reload() to
// read it again after a change.
export default function useLoad<T>(load: () => Promise<T>, deps: unknown[] = []) {
	const [value, setValue] = useState<T | undefined>(undefined);
	const [error, setError] = useState<string | undefined>(undefined);

	const reload = useCallback(async () => {
		try {
			setValue(await load());
			setError(undefined);
		} catch (e) {
			setError(errorOf(e));
		}
	}, deps);

	useEffect(() => {
		reload();
	}, [reload]);

	return { value, error, reload };
}
