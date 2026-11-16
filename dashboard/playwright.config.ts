import { defineConfig } from "@playwright/test";

// The dashboard against a real lugh-node (e2e/node.ts), in Chromium: one worker, since the tests
// share the node and walk one story, root's first sign-in onwards.
export default defineConfig({
	testDir: "e2e",
	workers: 1,
	fullyParallel: false,
	timeout: 60_000,
	reporter: [["list"]],
	use: { browserName: "chromium", trace: "retain-on-failure" },
});
