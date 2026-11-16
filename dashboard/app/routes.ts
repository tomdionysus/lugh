import { type RouteConfig, index, layout, route } from "@react-router/dev/routes";

// Everything sits inside the layout, which signs the person in first.
export default [
	layout("layouts/AdminLayout.tsx", [
		index("screens/Account.tsx"),
		route("users", "screens/Users.tsx"),
		route("users/:id", "screens/UserDetail.tsx"),
		route("groups", "screens/Groups.tsx"),
		route("groups/:id", "screens/GroupDetail.tsx"),
		route("policies", "screens/Policies.tsx"),
		route("apps", "screens/Apps.tsx"),
		route("keys", "screens/Keys.tsx"),
		route("audit", "screens/Audit.tsx"),
		route("*", "screens/NotFound.tsx"),
	]),
] satisfies RouteConfig;
