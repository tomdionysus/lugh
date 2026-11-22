// @lugh/admin-ui: the stack's one admin UI shell (Lugh's TODO/2026-11-20-dependants.md, "The shared
// admin UI"), carved from Lugh's dashboard. Lugh's dashboard consumes it as an npm workspace; Lir,
// Louhi, Mimir and Kvasir fetch Lugh's repository at a tag and depend on it by file path. It is
// source, TypeScript and CSS, compiled by the consumer's Vite; nothing is published.
//
// The styles are imported once, by the consumer's root: "@lugh/admin-ui/styles/reset.css" then
// "@lugh/admin-ui/styles/admin.css".

export { ApiClient, ApiError, errorOf, type Versioned } from "./lib/api";
export { when } from "./lib/format";
export { visible, type Section } from "./lib/sections";

export { ApiContext, useApi } from "./hooks/useApi";
export { useAct } from "./hooks/useAct";
export { useLoad } from "./hooks/useLoad";

export { Confirm, useConfirm } from "./components/Confirm";
export { Messages } from "./components/Messages";
export { NavBar } from "./components/NavBar";

export { AdminShell, type AdminShellProps } from "./layout/AdminShell";
