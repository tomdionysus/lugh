// @lugh/admin-ui: the stack's one admin UI shell (Lugh's TODO/2026-11-20-dependants.md, "The shared
// admin UI"), carved from Lugh's dashboard. Lugh's dashboard consumes it as an npm workspace; Lir,
// Louhi, Mimir and Kvasir fetch Lugh's repository at a tag and depend on it by file path. It is
// source, TypeScript and CSS, compiled by the consumer's Vite; nothing is published.
//
// The styles are imported once, by the consumer's root: "@lugh/admin-ui/styles/reset.css" then
// "@lugh/admin-ui/styles/admin.css".

export { ApiClient, ApiError, errorOf, type Versioned } from "./lib/api";
export { when } from "./lib/format";
export { challengeOf, finishLughSignIn, lughSignInUrl, type LughCode, type LughSignInConfig } from "./lib/lughSignIn";
export { visible, type Section } from "./lib/sections";

export { ApiContext, useApi } from "./hooks/useApi";
export { useAct } from "./hooks/useAct";
export { useCursorPages, type Page } from "./hooks/useCursorPages";
export { useEvents, type EventsOptions } from "./hooks/useEvents";
export { useLoad } from "./hooks/useLoad";

export { Confirm, useConfirm } from "./components/Confirm";
export { DataTable, type Column, type Paging } from "./components/DataTable";
export { DetailPanel, type Detail } from "./components/DetailPanel";
export { Messages } from "./components/Messages";
export { NavBar } from "./components/NavBar";
export { StatusPill, type Tone } from "./components/StatusPill";

export { AdminShell, type AdminShellProps } from "./layout/AdminShell";
export { SignIn } from "./screens/SignIn";
