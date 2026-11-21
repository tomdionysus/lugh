// A real lugh-node for the browser tests (P7): a fresh cluster made with `lugh-node init`, a
// certificate for localhost made with openssl, and the node serving the built dashboard with an
// issuer at https://localhost:<port>, so WebAuthn's RP ID is localhost. LUGH_NODE names the binary.
// Everything lives under test-results/node, inside the dashboard's own tree.

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { connect, createServer } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type Node = { url: string; password: string; spki: string; child: ChildProcess; log: string };

const here = dirname(fileURLToPath(import.meta.url));
const binary = process.env.LUGH_NODE ?? resolve(here, "../../build/lugh-node");
const home = resolve(here, "../test-results/node");

function run(command: string, args: string[], options: { input?: string; env?: NodeJS.ProcessEnv } = {}) {
	const ran = spawnSync(command, args, { input: options.input, env: options.env ?? process.env, maxBuffer: 1 << 20 });
	if (ran.status !== 0) throw new Error(`${command} ${args.join(" ")} failed: ${ran.stderr?.toString()}`);
	return ran;
}

// Whether something accepts a connection on the port.
function listening(port: number): Promise<boolean> {
	return new Promise(done => {
		const socket = connect(port, "127.0.0.1");
		socket.once("connect", () => {
			socket.destroy();
			done(true);
		});
		socket.once("error", () => done(false));
	});
}

async function freePort(): Promise<number> {
	return new Promise((done, failed) => {
		const server = createServer();
		server.once("error", failed);
		server.listen(0, "127.0.0.1", () => {
			const port = (server.address() as { port: number }).port;
			server.close(() => done(port));
		});
	});
}

// The environment without anything that would configure Lugh, as the process tests give it.
function cleanEnvironment(extra: Record<string, string> = {}) {
	const out: NodeJS.ProcessEnv = {};
	for (const [name, value] of Object.entries(process.env)) if (!name.startsWith("LUGH_") && name !== "CREDENTIALS_DIRECTORY") out[name] = value;
	return { ...out, ...extra };
}

export async function startNode(): Promise<Node> {
	rmSync(home, { recursive: true, force: true });
	mkdirSync(`${home}/credentials`, { recursive: true, mode: 0o700 });
	const certificate = `${home}/cert.pem`;
	const key = `${home}/key.pem`;
	run("openssl", [
		"req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-subj", "/CN=localhost",
		"-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", key, "-out", certificate,
	]);
	// The certificate's SPKI hash, which Chromium is told to trust: WebAuthn refuses a page with a
	// certificate error, so errors are not merely ignored.
	const spki = spawnSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${certificate}' | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`])
		.stdout.toString()
		.trim();

	// Genesis: the master key on standard output, root's password on standard error.
	const init = run(binary, ["init", "--state-directory", `${home}/state`], { env: cleanEnvironment() });
	writeFileSync(`${home}/credentials/lugh-master-key`, init.stdout, { mode: 0o600 });
	const lines = init.stderr.toString().split("\n");
	const at = lines.findIndex(line => line.startsWith("The root password"));
	const password = at >= 0 ? lines[at + 2].trim() : "";
	if (!password) throw new Error("no root password in:\n" + init.stderr.toString());

	const port = await freePort();
	const url = `https://localhost:${port}`;
	const child = spawn(
		binary,
		[
			"--tls-certificate", certificate, "--tls-key", key, "--state-directory", `${home}/state`, "--server-address", "127.0.0.1", "--server-port", String(port),
			"--oauth-issuer", url, "--static-directory", resolve(here, "../build/client"),
		],
		{ env: cleanEnvironment({ CREDENTIALS_DIRECTORY: `${home}/credentials` }), stdio: ["ignore", "pipe", "pipe"] },
	);
	let log = "";
	child.stdout?.on("data", chunk => (log += chunk));
	child.stderr?.on("data", chunk => (log += chunk));

	// Up when it accepts a connection; at most 15 seconds.
	const until = Date.now() + 15000;
	for (;;) {
		if (await listening(port)) break;
		if (Date.now() > until || child.exitCode !== null) throw new Error("lugh-node did not come up:\n" + log);
		await new Promise(done => setTimeout(done, 100));
	}
	return { url, password, spki, child, log };
}
