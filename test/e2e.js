// @ts-check
/**
 * End-to-end proxy test.
 *
 * Spawns the real proxy as a child process, drives a JSON-RPC conversation over
 * its stdin, and asserts what comes back on stdout. This is the only test that
 * proves the thing actually works as an MCP intermediary rather than just as a
 * library.
 *
 * Run: node test/e2e.js
 */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

let passed = 0;
let failed = 0;
/** @type {string[]} */
const failures = [];

/** @param {string} name @param {boolean} cond @param {string} [detail] */
function check(name, cond, detail = "") {
  if (cond) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    failures.push(`${name}${detail ? ` — ${detail}` : ""}`);
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

/**
 * Run one proxy session: send `requests`, collect stdout lines.
 * @param {object} opts
 * @param {string} opts.server        fixture path
 * @param {string} opts.mode
 * @param {string} [opts.blockAt]
 * @param {any[]} opts.requests
 * @returns {Promise<{responses:any[], stderr:string}>}
 */
function runSession({ server, mode, blockAt = "high", requests }) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [join(ROOT, "lib", "cli.js"), "wrap", "--mode", mode, "--block-at", blockAt, "--", process.execPath, server],
      { cwd: ROOT },
    );

    /** @type {any[]} */
    const responses = [];
    let stderr = "";
    let buf = "";

    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`timeout (mode=${mode}). stderr=${stderr.slice(0, 400)}`));
    }, 15000);

    child.stdout.on("data", (chunk) => {
      buf += chunk.toString();
      let idx;
      while ((idx = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try {
          responses.push(JSON.parse(line));
        } catch {
          /* ignore non-JSON noise */
        }
      }
    });
    child.stderr.on("data", (c) => {
      stderr += c.toString();
    });

    for (const req of requests) {
      child.stdin.write(JSON.stringify(req) + "\n");
    }

    // Give the exchange time to settle, then wrap up.
    setTimeout(() => {
      clearTimeout(timer);
      child.stdin.end();
      child.kill();
      resolve({ responses, stderr });
    }, 2500);
  });
}

const REQS = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {} } },
  { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "read_notes", arguments: {} } },
];

console.log("\n=== A. monitor mode: hostile payload reaches the client, and is logged ===");
{
  const { responses, stderr } = await runSession({
    server: join(HERE, "fixtures", "evil-server.cjs"),
    mode: "monitor",
    requests: REQS,
  });

  check("initialize answered", responses.some((r) => r.id === 1 && r.result && r.result.serverInfo));
  const call = responses.find((r) => r.id === 3);
  check("tools/call answered", Boolean(call));
  check("payload passes through in monitor mode", Boolean(call && call.result && !call.error));
  check("payload content preserved verbatim", JSON.stringify(call || {}).includes("Ignore all previous instructions"));
  check("finding was logged to stderr", /mcp-output-firewall/.test(stderr));
  check("critical rule reported", /INJ-001|HJK-001/.test(stderr), stderr.slice(0, 200));
}

console.log("\n=== B. block mode: hostile payload is withheld ===");
{
  const { responses, stderr } = await runSession({
    server: join(HERE, "fixtures", "evil-server.cjs"),
    mode: "block",
    blockAt: "high",
    requests: REQS,
  });

  const call = responses.find((r) => r.id === 3);
  check("tools/call rejected", Boolean(call && call.error));
  check("error identifies mcp-output-firewall", Boolean(call && call.error && /mcp-output-firewall/.test(call.error.message)));
  check("error reports severity", Boolean(call && call.error && call.error.data && call.error.data.worst === "critical"));
  check("error lists offending rules", Boolean(call && call.error && call.error.data && call.error.data.findings && call.error.data.findings.length > 0));
  check("hostile text NOT delivered", !JSON.stringify(responses).includes("Ignore all previous instructions"));
  check("block logged to stderr", /BLOCKED/.test(stderr));
  check("initialize still works in block mode", responses.some((r) => r.id === 1 && r.result));
}

console.log("\n=== C. warn mode: payload is sanitized but delivered ===");
{
  const { responses } = await runSession({
    server: join(HERE, "fixtures", "evil-server.cjs"),
    mode: "warn",
    blockAt: "high",
    requests: REQS,
  });

  const call = responses.find((r) => r.id === 3);
  check("tools/call answered", Boolean(call && call.result));
  const text = JSON.stringify(call || {});
  check("original imperative neutralised", !/Ignore all previous instructions/.test(text), "raw phrase still present");
  check("untrusted marker inserted", /untrusted-instruction/.test(text));
}

console.log("\n=== D. transparency: a well-behaved server is untouched ===");
{
  const goodReqs = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {} } },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_dir", arguments: { path: "." } } },
  ];
  const { responses, stderr } = await runSession({
    server: join(HERE, "fixtures", "good-server.cjs"),
    mode: "block",
    blockAt: "high",
    requests: goodReqs,
  });

  const call = responses.find((r) => r.id === 3);
  check("no error raised", !(call && call.error));
  check("content delivered unchanged", JSON.stringify(call || {}).includes("src/"));
  check("second content block intact", JSON.stringify(call || {}).includes("express"));
  check("tools/list passes through", responses.some((r) => r.id === 2 && r.result && r.result.tools));
  check("no block logged", !/BLOCKED/.test(stderr));
}

console.log("\n" + "=".repeat(60));
console.log(`passed: ${passed}   failed: ${failed}`);
if (failed > 0) {
  console.log("\nfailures:");
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
console.log("all green\n");
