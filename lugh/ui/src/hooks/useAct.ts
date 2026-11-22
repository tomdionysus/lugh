import { useState } from "react";

import { errorOf } from "../lib/api";

// A change made from a screen: its error or its confirmation, shown once, and then whatever must
// be read again.
export function useAct(after?: () => Promise<unknown> | void) {
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");

	const act = async (what: () => Promise<unknown>, done?: string) => {
		setError("");
		setMessage("");
		try {
			await what();
			if (done) setMessage(done);
			if (after) await after();
			return true;
		} catch (e) {
			setError(errorOf(e));
			return false;
		}
	};

	return { act, error, message };
}
