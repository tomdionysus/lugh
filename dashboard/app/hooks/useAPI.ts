import { createContext, useContext } from "react";

import { API } from "../lib/API";

// One API for the whole dashboard, given by the layout; a test gives its own.
export const ApiContext = createContext<API>(new API());

export default function useAPI() {
	return useContext(ApiContext);
}
