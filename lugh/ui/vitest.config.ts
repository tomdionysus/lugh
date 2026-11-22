import { defineConfig } from "vitest/config";

// The package's components, hooks and API client, in Vitest's browser mode (Chromium, through
// Playwright), as the dashboard's are.
export default defineConfig({
	test: {
		include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
		browser: {
			enabled: true,
			provider: "playwright",
			headless: true,
			instances: [{ browser: "chromium" }],
		},
	},
});
