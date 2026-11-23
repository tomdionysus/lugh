import { useApi } from "@lugh/admin-ui";

import type { API } from "../lib/API";

// Lugh's API, as the layout gave it (@lugh/admin-ui's ApiContext); a test gives its own.
export default function useAPI() {
	return useApi<API>();
}
