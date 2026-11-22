import { defineConfig } from "vitest/config";

// The package's components, hooks and API client.
export default defineConfig({
	test: {
		environment: "jsdom",
		include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
	},
});
