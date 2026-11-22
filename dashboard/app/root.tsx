import { isRouteErrorResponse, Links, Meta, Outlet, Scripts, ScrollRestoration } from "react-router";

import type { Route } from "./+types/root";
import "@fontsource-variable/roboto/wght.css";
import "@lugh/admin-ui/styles/reset.css";
import "@lugh/admin-ui/styles/admin.css";
import "./lugh.css";

export function meta() {
	return [{ title: "Lugh" }];
}

export function Layout({ children }: { children: React.ReactNode }) {
	return (
		<html lang="en">
			<head>
				<meta charSet="utf-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1" />
				<Meta />
				<Links />
			</head>
			<body>
				<div className="main">{children}</div>
				<ScrollRestoration />
				<Scripts />
			</body>
		</html>
	);
}

export default function App() {
	return <Outlet />;
}

// Without this, React Router puts its own placeholder in the generated index.html.
export function HydrateFallback() {
	return (
		<div className="hydrate-fallback">
			<p>Loading</p>
		</div>
	);
}

export function ErrorBoundary({ error }: Route.ErrorBoundaryProps) {
	let message = "Error";
	let details = "Something went wrong.";
	if (isRouteErrorResponse(error)) {
		message = error.status === 404 ? "404" : "Error";
		details = error.status === 404 ? "There is no such page." : error.statusText || details;
	} else if (import.meta.env.DEV && error instanceof Error) {
		details = error.message;
	}
	return (
		<main className="error-page">
			<h1>{message}</h1>
			<p>{details}</p>
		</main>
	);
}
