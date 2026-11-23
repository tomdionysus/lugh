import { createContext, useContext } from "react";

import { ApiClient } from "../lib/api";

// One API client for the whole UI, given by the layout; a test gives its own.
export const ApiContext = createContext<ApiClient>(new ApiClient());

// The client the layout gave, as the UI's own subclass of ApiClient.
export function useApi<T extends ApiClient = ApiClient>(): T {
	return useContext(ApiContext) as T;
}
