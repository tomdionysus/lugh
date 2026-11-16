import { defineConfig } from "vitest/config";
import tsconfigPaths from "vite-tsconfig-paths";

// The components and lib/API.ts, in jsdom, without React Router's build plugin.
export default defineConfig({
	plugins: [tsconfigPaths()],
	test: {
		environment: "jsdom",
		include: ["app/**/*.test.ts", "app/**/*.test.tsx"],
	},
});
