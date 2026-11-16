import { reactRouter } from "@react-router/dev/vite";
import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";

// Under `npm run dev`, Vite forwards Lugh's own paths to a running lugh-node, so the dashboard
// calls its own origin in development exactly as it does in production: no CORS, and the
// session cookie is simply sent. LUGH_URL names the node (its certificate is not checked here,
// in development only).
const lugh = process.env.LUGH_URL ?? "https://127.0.0.1:8443";
const forward = { target: lugh, secure: false, changeOrigin: false };

export default defineConfig({
	plugins: [reactRouter(), tsconfigPaths()],
	server: {
		proxy: {
			"/api": forward,
			"/signin": forward,
			"/signout": forward,
			"/oauth2": forward,
			"/.well-known": forward,
			"/health": forward,
		},
	},
});
