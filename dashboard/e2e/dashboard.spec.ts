import { chromium, expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";

import { startNode, type Node } from "./node";

// The dashboard on a real lugh-node (P7): root's first sign-in, from the dashboard, enrolling a
// passkey (Chromium's virtual authenticator); the dashboard at phr administering; and root
// coming back later with the passkey alone. One story, in order.

let node: Node;
let browser: Browser;
let context: BrowserContext;
let page: Page;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
	node = await startNode();
	// The node's certificate trusted by its key, so the page is a secure context WebAuthn runs in.
	browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${node.spki}`] });
	context = await browser.newContext();
	page = await context.newPage();
	// A platform authenticator that holds discoverable credentials and verifies its user.
	const cdp = await context.newCDPSession(page);
	await cdp.send("WebAuthn.enable");
	await cdp.send("WebAuthn.addVirtualAuthenticator", {
		options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
	});
});

test.afterAll(async () => {
	await browser?.close();
	node?.child.kill("SIGTERM");
});

test("root's first sign-in enrols a passkey and lands on the dashboard at phr", async () => {
	await page.goto(node.url + "/");
	await expect(page).toHaveURL(/\/signin\?continue=dashboard/);
	await page.fill("input[name=login]", "root");
	await page.fill("input[name=password]", node.password);
	await page.click("form[action='/signin'] button[type=submit]");
	await expect(page).toHaveURL(/\/signin\/enrol\/totp/);

	await page.click("button[data-webauthn=enrol]");
	await expect(page.getByText("Your recovery codes")).toBeVisible();
	await page.getByText("I have kept them").click();

	await expect(page).toHaveURL(node.url + "/");
	await expect(page.locator(".status")).toHaveText("Passkey");
	await expect(page.locator(".nav-item", { hasText: "Users" })).toBeVisible();
	await expect(page.getByText("Administering needs a sign-in")).toHaveCount(0);
});

test("root adds a person and makes their enrolment link", async () => {
	await page.locator(".nav-item", { hasText: "Users" }).click();
	await page.getByLabel("Name", { exact: true }).fill("alice");
	await page.getByLabel("Address", { exact: true }).fill("alice@example.test");
	await page.getByRole("button", { name: "Add user" }).click();
	await expect(page).toHaveURL(/\/users\/.+/);
	await expect(page.locator(".pill", { hasText: "Not enrolled" })).toBeVisible();
	await page.getByRole("button", { name: "Make an enrolment link" }).click();
	await expect(page.locator(".secret-once")).toContainText("/signin/enrol/");
});

test("root makes a group and puts alice in it", async () => {
	await page.locator(".nav-item", { hasText: "Groups" }).click();
	await page.getByLabel("Name", { exact: true }).fill("operators");
	await page.getByRole("button", { name: "Add group" }).click();
	await expect(page.getByRole("heading", { name: "operators" })).toBeVisible();
	await page.getByLabel("User to add").selectOption({ label: "alice" });
	await page.getByRole("button", { name: "Add", exact: true }).click();
	await expect(page.getByRole("link", { name: "alice" })).toBeVisible();
});

test("the account shows root's passkey, and the audit log what was done", async () => {
	await page.locator(".nav-item", { hasText: "Account" }).click();
	await expect(page.getByRole("cell", { name: "Passkey" }).first()).toBeVisible();
	await page.locator(".nav-item", { hasText: "Audit" }).click();
	await expect(page.getByText("user.create").first()).toBeVisible();
	await page.getByRole("button", { name: "Verify the chain" }).click();
	await expect(page.getByText(/^Intact/)).toBeVisible();
});

test("signed out, root comes back with the passkey alone", async () => {
	await page.getByRole("button", { name: "Sign out" }).click();
	await expect(page.getByText("You are signed out.")).toBeVisible();
	await page.goto(node.url + "/");
	await expect(page).toHaveURL(/\/signin\?continue=dashboard/);
	await page.click("button[data-webauthn=passkey]");
	await expect(page).toHaveURL(node.url + "/");
	await expect(page.locator(".status")).toHaveText("Passkey");
});
