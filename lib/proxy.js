// @ts-check
/**
 * mcp-output-firewall — MCP proxy (runtime)
 *
 * Sits between an MCP client (Claude Desktop, Cursor, your own agent) and one or
 * more MCP servers. It is a transparent stdio JSON-RPC relay with three
 * independent inspection layers:
 *
 *   Layer 1 — content     (server→client)  Is the payload safe to read?
 *             Pattern and normalisation scan of every tool result, resource and
 *             prompt on the way back to the agent.
 *
 *   Layer 2 — egress      (client→server)  Where is this call trying to reach?
 *             Inspects tool-call arguments for destinations. This is the layer
 *             that catches the attack the content scanner structurally cannot
 *             see: a benign tool invoked with a hostile argument.
 *
 *   Layer 3 — action      (client→server)  Should this call happen at all?
 *             Deterministic policy for consequential operations. No scanner is
 *             probabilistic here; this layer is not a judgement call.
 *
 * Layers 2 and 3 exist precisely because layer 1 is defeatable. A single-layer
 * content filter is a claim; three layers with different failure modes is a
 * posture.
 *
 * Modes (layer 1):
 *   monitor  — log findings, pass everything through (default; safe to try)
 *   warn     — sanitize suspicious content in band, then pass it through
 *   block    — refuse to deliver a message whose worst finding >= threshold
 *
 * Dependency-free and speaks raw JSON-RPC over newline-delimited stdio, so it
 * works with any MCP server regardless of SDK version.
 */

import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { createInterface } from "node:readline";
import { scanDeep, sanitize } from "./rules.js";
import { evaluateCall, parseAllowList } from "./egress.js";
import {
  classifyCall,
  isTrustlisted,
  actionDenial,
  confirmationRequired,
} from "./action.js";

/** @typedef {'monitor'|'warn'|'block'} ProxyMode */
/** @typedef {import('./rules.js').Severity} Severity */
/** @typedef {import('./rules.js').Finding} Finding */

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

/** @param {Array<{severity:Severity}>} findings @returns {Severity} */
function worstOf(findings) {
  return findings.reduce(
    (acc, f) => (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[acc] ? f.severity : acc),
    /** @type {Severity} */ ("low"),
  );
}

/**
 * Recursively pull every string out of a value and rebuild it with the
 * transformer applied.
 * @param {unknown} value
 * @param {(s:string)=>string} fn
 * @param {number} [depth]
 * @returns {unknown}
 */
function mapStrings(value, fn, depth = 0) {
  if (depth > 32) return value;
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((v) => mapStrings(v, fn, depth + 1));
  if (value && typeof value === "object") {
    /** @type {Record<string,unknown>} */
    const out = {};
    for (const [k, v] of Object.entries(/** @type {Record<string,unknown>} */ (value))) {
      out[k] = mapStrings(v, fn, depth + 1);
    }
    return out;
  }
  return value;
}

export class SentryProxy extends EventEmitter {
  /** @param {any} options */
  constructor(options) {
    super();
    this.opts = {
      ...options,
      mode: options.mode || "monitor",
      blockAt: options.blockAt || "high",
      // Layer 2/3 switches. Off unless the operator asks for them: a policy
      // that silently starts refusing calls is worse than no policy.
      egressPolicy: options.egressAllow !== undefined || options.egressStrict
        ? {
            allow: parseAllowList(options.egressAllow || ""),
            allowPrivate: Boolean(options.egressAllowPrivate),
          }
        : null,
      egressStrict: Boolean(options.egressStrict),
      actionPolicy: Boolean(options.confirmActions),
      trustTools: options.trustTools || [],
      onConfirm: options.onConfirm || null,
    };
    /** @type {import('node:child_process').ChildProcessWithoutNullStreams|null} */
    this.child = null;
    this.stats = {
      inbound: 0,
      outbound: 0,
      findings: 0,
      blocked: 0,
      rewritten: 0,
      errors: 0,
      egressChecks: 0,
      egressBlocks: 0,
      actionChecks: 0,
      actionBlocks: 0,
    };
  }

  getStats() {
    return { ...this.stats };
  }

  /** Launch the upstream server and wire up the relay. */
  start() {
    const { command, args = [], env, cwd } = this.opts;
    this.child = /** @type {any} */ (
      spawn(command, args, {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, ...(env || {}) },
        cwd,
        shell: process.platform === "win32",
      })
    );

    // --- client -> server: layers 2 and 3 live here ------------------------
    const clientToServer = createInterface({ input: process.stdin, crlfDelay: Infinity });
    clientToServer.on("line", (line) => {
      if (!line.trim()) return;
      this.stats.inbound++;

      /** @type {any} */
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        // Not JSON-RPC. Forward untouched rather than break the pipe.
        this.child.stdin.write(line + "\n");
        return;
      }

      const verdict = this.inspectOutbound(msg);
      if (verdict) {
        process.stdout.write(JSON.stringify(verdict) + "\n");
        return;
      }
      this.child.stdin.write(line + "\n");
    });

    // --- server -> client: inspect here -----------------------------------
    const serverToClient = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    serverToClient.on("line", (line) => {
      if (!line.trim()) return;
      this.stats.outbound++;

      /** @type {any} */
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        // Not JSON-RPC. Pass through untouched rather than break the pipe.
        process.stdout.write(line + "\n");
        return;
      }

      const inspected = this.inspect(msg);
      if (inspected && inspected.blocked) {
        this.stats.blocked++;
        process.stdout.write(JSON.stringify(this.denial(msg, inspected)) + "\n");
        return;
      }
      process.stdout.write((inspected && inspected.serialized ? inspected.serialized : line) + "\n");
    });

    this.child.stderr.on("data", (buf) => {
      if (this.opts.debug) process.stderr.write(`[mcp-output-firewall:upstream] ${buf.toString()}`);
    });

    this.child.on("exit", (code, signal) => {
      if (this.opts.debug) process.stderr.write(`[mcp-output-firewall] upstream exited code=${code} signal=${signal}\n`);
      this.emit("exit", { code, signal });
      process.exit(code || 0);
    });

    this.child.on("error", (err) => {
      process.stderr.write(`[mcp-output-firewall] failed to start upstream: ${err.message}\n`);
      process.exit(1);
    });

    process.stdin.on("end", () => this.child.stdin.end());
    process.on("SIGINT", () => this.stop());
    process.on("SIGTERM", () => this.stop());
  }

  stop() {
    try {
      if (this.child) this.child.kill();
    } catch {
      /* already gone */
    }
  }

  /**
   * Inspect one client→server message against layers 2 and 3.
   *
   * Returns a JSON-RPC error object when the call must not proceed, or null to
   * let it through. Only `tools/call` is inspected: everything else is protocol
   * handshake traffic with nothing to police.
   *
   * @param {any} msg
   * @returns {any|null}
   */
  inspectOutbound(msg) {
    if (msg.method !== "tools/call") return null;
    const params = msg.params || {};
    const tool = String(params.name || "");
    const args = params.arguments;

    // ---- Layer 3: action policy -----------------------------------------
    if (this.opts.actionPolicy) {
      const verdict = classifyCall({ tool, args });
      if (verdict && !isTrustlisted(tool, this.opts.trustTools)) {
        this.stats.actionChecks++;
        const event = {
          direction: /** @type {const} */ ("client->server"),
          layer: /** @type {const} */ ("action"),
          tool,
          verdict,
          at: new Date().toISOString(),
        };
        if (verdict.verdict === "block") {
          this.stats.actionBlocks++;
          this.emit("action-block", event);
          this.log(`ACTION-BLOCK ${tool} rule=${verdict.ruleId} (${verdict.reason})`);
          return actionDenial(msg, verdict);
        }
        // "confirm": an interactive approver may say yes; unattended, we refuse.
        const approved = this.opts.onConfirm ? this.opts.onConfirm(event) : false;
        if (!approved) {
          this.stats.actionBlocks++;
          this.emit("action-confirm", event);
          this.log(`ACTION-CONFIRM ${tool} rule=${verdict.ruleId} (${verdict.reason})`);
          return confirmationRequired(msg, verdict);
        }
        this.emit("action-approved", event);
      }
    }

    // ---- Layer 2: egress policy -----------------------------------------
    if (this.opts.egressPolicy) {
      this.stats.egressChecks++;
      const verdicts = evaluateCall({ tool, args }, this.opts.egressPolicy);
      const blocking = verdicts.filter((v) => v.action === "block");
      const unknown = verdicts.filter((v) => v.action === "allow");

      if (blocking.length > 0) {
        this.stats.egressBlocks++;
        const event = {
          direction: /** @type {const} */ ("client->server"),
          layer: /** @type {const} */ ("egress"),
          tool,
          verdicts,
          at: new Date().toISOString(),
        };
        this.emit("egress-block", event);
        this.log(
          `EGRESS-BLOCK ${tool} -> ${blocking.map((v) => `${v.host} (${v.reason})`).join("; ")}`,
        );
        return this.egressDenial(msg, tool, blocking);
      }

      if (unknown.length > 0) {
        for (const v of unknown) {
          this.log(`EGRESS-ALLOW ${tool} -> ${v.host} (unrecognised, not blocked)`);
        }
        this.emit("egress-observed", {
          direction: /** @type {const} */ ("client->server"),
          layer: /** @type {const} */ ("egress"),
          tool,
          verdicts,
        });
      }
    }

    return null;
  }

  /**
   * @param {any} msg
   * @param {string} tool
   * @param {any[]} blocking
   */
  egressDenial(msg, tool, blocking) {
    return {
      jsonrpc: "2.0",
      id: msg.id === undefined ? null : msg.id,
      error: {
        code: -32004,
        message:
          `mcp-output-firewall: egress blocked — ${tool} attempted to reach ` +
          `${blocking.map((v) => v.host).join(", ")}. ` +
          `Add the host to --egress-allow if this is intended.`,
        data: {
          blockedBy: "mcp-output-firewall",
          layer: "egress",
          tool,
          destinations: blocking.map((v) => ({ host: v.host, reason: v.reason })),
        },
      },
    };
  }

  /** @param {string} text */
  log(text) {
    if (this.opts.quiet) return;
    process.stderr.write(`[mcp-output-firewall] ${text}\n`);
  }

  /**
   * Build a JSON-RPC error to send in place of a poisoned result, so the
   * client fails loudly instead of silently consuming attacker-controlled data.
   * @param {any} msg
   * @param {any} inspected
   */
  denial(msg, inspected) {
    return {
      jsonrpc: "2.0",
      id: msg.id === undefined ? null : msg.id,
      error: {
        code: -32001,
        message:
          `mcp-output-firewall: response blocked (${inspected.worst}) — ` +
          inspected.findings
            .slice(0, 3)
            .map((/** @type {any} */ f) => f.ruleId)
            .join(", "),
        data: {
          blockedBy: "mcp-output-firewall",
          worst: inspected.worst,
          findings: inspected.findings.slice(0, 5).map((/** @type {any} */ f) => ({
            ruleId: f.ruleId,
            severity: f.severity,
            path: f.path,
          })),
        },
      },
    };
  }

  /**
   * Inspect one server→client message. Returns null when there is nothing
   * worth reporting (the common case, kept fast).
   * @param {any} msg
   * @returns {any|null}
   */
  inspect(msg) {
    const payload = msg.result !== undefined ? msg.result : msg.params;
    if (payload === undefined || payload === null) return null;

    const findings = scanDeep(payload, this.opts.scanOptions);
    if (findings.length === 0) return null;

    this.stats.findings += findings.length;
    const worst = worstOf(findings);
    const overThreshold = SEVERITY_ORDER[worst] >= SEVERITY_ORDER[this.opts.blockAt];

    const event = {
      direction: /** @type {const} */ ("server->client"),
      method: msg.method !== undefined ? msg.method : msg.id !== undefined ? `response#${String(msg.id)}` : null,
      findings,
      worst,
      blocked: this.opts.mode === "block" && overThreshold,
      rewritten: false,
      serialized: /** @type {string|undefined} */ (undefined),
    };

    if (!event.blocked && this.opts.mode !== "monitor" && overThreshold) {
      const before = JSON.stringify(msg.result);
      msg.result = mapStrings(msg.result, (s) => sanitize(s, this.opts.scanOptions).text);
      const after = JSON.stringify(msg.result);
      if (before !== after) {
        event.rewritten = true;
        event.serialized = JSON.stringify(msg);
        this.stats.rewritten++;
      }
    }

    if (event.blocked) this.emit("block", event);
    else if (event.rewritten) this.emit("warn", event);
    else this.emit("finding", event);

    if (this.opts.onFinding) this.opts.onFinding(event);
    return event;
  }
}

/**
 * Long-lived proxy entry point used by the CLI.
 * @param {any} options
 * @returns {SentryProxy}
 */
export function runProxy(options) {
  const proxy = new SentryProxy(options);

  if (!options.quiet) {
    const label = options.mode === "monitor" ? "seen" : "flagged";
    proxy.on(options.mode === "monitor" ? "finding" : "warn", (/** @type {any} */ e) => {
      process.stderr.write(
        `[mcp-output-firewall] ${label} ${e.worst} in ${e.method || "?"}: ${e.findings
          .map((/** @type {any} */ f) => f.ruleId)
          .join(",")}${e.rewritten ? " (sanitized)" : ""}\n`,
      );
    });
    proxy.on("block", (/** @type {any} */ e) => {
      process.stderr.write(
        `[mcp-output-firewall] BLOCKED ${e.method || "?"} worst=${e.worst} rules=${e.findings
          .map((/** @type {any} */ f) => f.ruleId)
          .join(",")}\n`,
      );
    });
    proxy.on("action-approved", (/** @type {any} */ e) => {
      process.stderr.write(
        `[mcp-output-firewall] ACTION-APPROVED ${e.tool} rule=${e.verdict.ruleId}\n`,
      );
    });
  }

  proxy.start();
  return proxy;
}
