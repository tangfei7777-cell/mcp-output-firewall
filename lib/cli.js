#!/usr/bin/env node
// @ts-check
/**
 * mcp-output-firewall CLI
 *
 *   mcp-output-firewall wrap [opts] -- <command> [args...]  Run an MCP server behind the firewall
 *   mcp-output-firewall serve [opts]                        Run the firewall itself as an MCP server
 *   mcp-output-firewall scan [opts] [file...]               Scan files or stdin for poisoned content
 *   mcp-output-firewall bench [opts]                        Score the engine against the adversarial corpus
 *   mcp-output-firewall rules                               Print the rule catalogue
 *   mcp-output-firewall install --client <name> -- <cmd>    Print the client config snippet
 */

import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { scan, listRules } from "./rules.js";
import { renderScanResult, toJsonReport, exitCodeFor } from "./report.js";
import { runProxy } from "./proxy.js";
import { runServe } from "./serve.js";
import { DEMO_SAMPLES } from "./demo.js";
import { runBenchmark, renderBench, toJsonBench } from "./benchmark.js";

const VERSION = "0.3.0";

const HELP = `
mcp-output-firewall ${VERSION} — three-layer output firewall for MCP servers

  layer 1  content   (server -> client)  is the payload safe to read?
  layer 2  egress    (client -> server)  where is this tool call going?
  layer 3  action    (client -> server)  should this call happen at all?

USAGE
  mcp-output-firewall wrap [options] -- <command> [args...]
      Launch an MCP server with every response inspected before it reaches
      your agent.

      Layer 1
      --mode <monitor|warn|block>   Enforcement. Default: monitor
      --block-at <low|medium|high|critical>
                                    Severity threshold. Default: high

      Layer 2 — off unless you pass one of these
      --egress-allow <host,host>    Hosts the agent may talk to
      --egress-strict               Check egress even with an empty allow-list
      --egress-allow-private        Permit RFC1918 / loopback destinations

      Layer 3 — off unless you pass one of these
      --confirm-actions             Apply the action policy
      --trust-tools <a,b>           Tools never subject to the action policy

      --quiet                       Suppress log lines
      --debug                       Forward upstream stderr

  mcp-output-firewall serve [options]
      Run the firewall itself as an MCP server on stdio, so an agent can call
      the three layers instead of only being wrapped by them. Exposes four
      tools:

        check_tool_call        may I run this call?            (layers 2 + 3)
        scan_content           is this payload safe to read?   (layer 1)
        evaluate_tool_result   may I hand this to the model?   (layer 1, verdict)
        describe_policy        what is covered, what is missed?

      Speaks both protocol eras: modern revisions (2026-07-28 and later, which
      carry version and capabilities per request in _meta, no handshake) and
      legacy ones (2025-11-25 and earlier, initialize handshake). Implements
      server/discover, which modern clients probe with.

      Run with no arguments while stdin is a pipe, the CLI serves as well, so a
      client config that omits the subcommand still connects. A terminal with no
      arguments still gets this help.

      --quiet                       Suppress the startup line

  mcp-output-firewall scan [options] [file...]
      Scan files (or stdin when no file is given) for prompt injection,
      exfiltration payloads and leaked secrets.

      --demo                        Scan the built-in attack samples
      --min-severity <level>        Only report at/above this level. Default: low
      --format <text|json>          Output format. Default: text
      --max-hits <n>                Cap hits per rule. Default: 5
      --raw                         Include unmasked evidence

  mcp-output-firewall bench [options]
      Score the engine against the adversarial corpus and print the scorecard.
      Reports catch rate, known gaps and false-positive rate separately.

      --format <text|json>          Output format. Default: text
      --fail-on-miss                Exit 1 if any claimed detection regressed

  mcp-output-firewall rules
      Print every rule with the attack it stops and the suggested fix.

  mcp-output-firewall install --client <claude|cursor|vscode|generic> [--name <n>] -- <command> [args...]
      Print the MCP client config needed to put a server behind mcp-output-firewall.

EXIT CODES
  0 clean  ·  1 findings at/above the threshold  ·  2 usage error

EXAMPLES
  # Layer 1 only: watch what a server returns, change nothing
  mcp-output-firewall wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # Run it as an MCP server your agent can call before it acts
  mcp-output-firewall serve

  # All three layers on
  mcp-output-firewall wrap --mode block --block-at high \\
      --egress-allow api.github.com,registry.npmjs.org --egress-strict \\
      --confirm-actions --trust-tools read_file,list_directory \\
      -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # Check the engine's honesty before trusting it
  mcp-output-firewall bench

  # Scan a suspicious tool result you already captured
  cat suspicious.json | mcp-output-firewall scan --min-severity medium
`;

/**
 * @param {string[]} argv
 */
function parseArgs(argv) {
  const [command = "help", ...rest] = argv;
  /** @type {string[]} */
  const positional = [];
  /** @type {Record<string, string|boolean>} */
  const flags = {};
  const valueFlags = new Set([
    "mode",
    "block-at",
    "min-severity",
    "max-hits",
    "format",
    "client",
    "name",
    "egress-allow",
    "trust-tools",
  ]);

  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--") {
      positional.push(...rest.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const key = a.slice(2);
        const next = rest[i + 1];
        if (next !== undefined && !next.startsWith("--") && valueFlags.has(key)) {
          flags[key] = next;
          i++;
        } else {
          flags[key] = true;
        }
      }
    } else {
      positional.push(a);
    }
  }
  return { command, positional, flags };
}

/** @param {string} msg */
function fail(msg) {
  process.stderr.write(`mcp-output-firewall: ${msg}\n`);
  process.exit(2);
}

/**
 * @param {string|boolean|undefined} v
 * @param {any} fallback
 */
function severityFlag(v, fallback) {
  if (typeof v !== "string") return fallback;
  const ok = ["low", "medium", "high", "critical"];
  if (!ok.includes(v)) fail(`invalid severity "${v}" (expected ${ok.join("|")})`);
  return v;
}

function readStdin() {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

/** @param {any} args */
function cmdScan(args) {
  const minSeverity = severityFlag(args.flags["min-severity"], "low");
  const format = typeof args.flags.format === "string" ? args.flags.format : "text";
  const maxHits = Number(args.flags["max-hits"] || 5);
  const scanOptions = {
    minSeverity,
    maxHitsPerRule: maxHits,
    includeRawEvidence: Boolean(args.flags.raw),
  };

  /** @type {Record<string, any>} */
  const results = {};

  if (args.flags.demo) {
    for (const sample of DEMO_SAMPLES) {
      results[sample.name] = scan(sample.content, scanOptions);
    }
  } else if (args.positional.length > 0) {
    for (const p of args.positional) {
      const path = resolve(p);
      if (!existsSync(path)) fail(`no such file: ${p}`);
      if (statSync(path).isDirectory()) fail(`is a directory: ${p}`);
      results[p] = scan(readFileSync(path, "utf8"), scanOptions);
    }
  } else {
    const text = readStdin();
    if (!text) fail("no input. Provide a file, pipe stdin, or use --demo");
    results["<stdin>"] = scan(text, scanOptions);
  }

  if (format === "json") {
    process.stdout.write(toJsonReport(results) + "\n");
  } else {
    for (const [label, r] of Object.entries(results)) {
      process.stdout.write(renderScanResult(r, label) + "\n");
    }
    const total = Object.values(results).reduce((n, r) => n + r.findings.length, 0);
    process.stdout.write(`— ${total} finding(s) across ${Object.keys(results).length} target(s)\n`);
  }

  process.exit(exitCodeFor(results, minSeverity));
}

/** @param {any} args */
function cmdWrap(args) {
  if (args.positional.length === 0) {
    fail("wrap needs a command, e.g. `mcp-output-firewall wrap -- npx -y some-mcp-server`");
  }
  const mode = typeof args.flags.mode === "string" ? args.flags.mode : "monitor";
  if (!["monitor", "warn", "block"].includes(mode)) fail(`invalid --mode "${mode}"`);

  const [command, ...cmdArgs] = args.positional;
  runProxy({
    command,
    args: cmdArgs,
    mode,
    blockAt: severityFlag(args.flags["block-at"], "high"),
    debug: Boolean(args.flags.debug),
    quiet: Boolean(args.flags.quiet),
    // Layer 2
    egressAllow: typeof args.flags["egress-allow"] === "string" ? args.flags["egress-allow"] : undefined,
    egressStrict: Boolean(args.flags["egress-strict"]),
    egressAllowPrivate: Boolean(args.flags["egress-allow-private"]),
    // Layer 3
    confirmActions: Boolean(args.flags["confirm-actions"]),
    trustTools:
      typeof args.flags["trust-tools"] === "string"
        ? args.flags["trust-tools"].split(",").map((s) => s.trim()).filter(Boolean)
        : [],
  });
}

/** @param {any} args */
function cmdServe(args) {
  runServe({ quiet: Boolean(args.flags.quiet) });
}

/** @param {any} args */
function cmdBench(args) {
  const report = runBenchmark();
  const format = typeof args.flags.format === "string" ? args.flags.format : "text";
  process.stdout.write(format === "json" ? toJsonBench(report) + "\n" : renderBench(report));

  // A regression in a claimed detection is a build failure, not a statistic.
  if (args.flags["fail-on-miss"] && report.catchRate.missed > 0) process.exit(1);
  process.exit(0);
}

function cmdRules() {
  const rules = listRules();
  process.stdout.write(`mcp-output-firewall rule catalogue — ${rules.length} rules\n\n`);
  for (const r of rules) {
    process.stdout.write(`[${r.id}] ${r.title}\n`);
    process.stdout.write(`  severity  : ${r.severity}\n`);
    process.stdout.write(`  category  : ${r.category}\n`);
    process.stdout.write(`  stops     : ${r.why}\n`);
    process.stdout.write(`  remediate : ${r.fix}\n\n`);
  }
}

/** @param {any} args */
function cmdInstall(args) {
  const client = typeof args.flags.client === "string" ? args.flags.client : "generic";
  const name = typeof args.flags.name === "string" ? args.flags.name : "my-server";
  const target = args.positional;

  if (target.length === 0) {
    fail("install needs the server command after `--`, e.g. `-- npx -y @modelcontextprotocol/server-filesystem /tmp`");
  }

  const entry = {
    command: "npx",
    args: ["-y", "mcp-output-firewall", "wrap", "--mode", "block", "--block-at", "high", "--", ...target],
  };

  if (client === "claude") {
    process.stdout.write(
      `Add this to claude_desktop_config.json (Settings -> Developer -> Edit Config):\n\n` +
        JSON.stringify({ mcpServers: { [name]: entry } }, null, 2) +
        `\n\nRestart Claude Desktop afterwards.\n`,
    );
  } else if (client === "cursor") {
    process.stdout.write(
      `Add this to .cursor/mcp.json (project) or ~/.cursor/mcp.json (global):\n\n` +
        JSON.stringify({ mcpServers: { [name]: entry } }, null, 2) +
        `\n`,
    );
  } else if (client === "vscode") {
    process.stdout.write(
      `Add this to .vscode/mcp.json:\n\n` +
        JSON.stringify({ servers: { [name]: { type: "stdio", ...entry } } }, null, 2) +
        `\n`,
    );
  } else {
    process.stdout.write(
      `Generic stdio MCP server entry — point your client at this command:\n\n` +
        JSON.stringify({ mcpServers: { [name]: entry } }, null, 2) +
        `\n\nAny MCP client that supports stdio transport works: the proxy is a\n` +
        `transparent JSON-RPC relay, so the server needs no modification.\n`,
    );
  }
}

function main() {
  const argv = process.argv.slice(2);

  // Invoked with no arguments and a piped stdin, this process was launched by a
  // program rather than by a person: an MCP client spawning a stdio server does
  // exactly that. Serve, instead of printing a help screen into a pipe nobody
  // is reading and exiting — which is what a client would see as a server that
  // dies on startup.
  //
  // A terminal, or any explicit subcommand, keeps the ordinary CLI behaviour.
  // `--help` in a pipe still means help, because it was asked for by name.
  if (argv.length === 0 && !process.stdin.isTTY) {
    cmdServe({ flags: {} });
    return;
  }

  const args = parseArgs(argv);
  switch (args.command) {
    case "wrap":
      cmdWrap(args);
      break;
    case "serve":
      cmdServe(args);
      break;
    case "scan":
      cmdScan(args);
      break;
    case "bench":
      cmdBench(args);
      break;
    case "rules":
      cmdRules();
      break;
    case "install":
      cmdInstall(args);
      break;
    case "version":
    case "--version":
    case "-v":
      process.stdout.write(`mcp-output-firewall ${VERSION}\n`);
      break;
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(HELP);
      break;
    default:
      process.stderr.write(`mcp-output-firewall: unknown command "${args.command}"\n${HELP}`);
      process.exit(2);
  }
}

main();
