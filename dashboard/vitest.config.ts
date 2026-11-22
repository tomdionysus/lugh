import { defineConfig } from "vitest/config";
import tsconfigPaths from "vite-tsconfig-paths";

// The dashboard's tests, the screens' story included, in Vitest's browser mode (Chromium, through
// Playwright), without React Router's build plugin: one runner for @lugh/admin-ui and the
// dashboard (the maintainer, 2026-11-22).
export default defineConfig({
	plugins: [tsconfigPaths()],
	test: {
		include: ["app/**/*.test.ts", "app/**/*.test.tsx"],
		browser: {
			enabled: true,
			provider: "playwright",
			headless: true,
			instances: [{ browser: "chromium" }],
		},
	},
});
