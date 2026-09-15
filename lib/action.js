// @ts-check
/**
 * mcp-output-firewall — action policy (runtime)
 *
 * The third layer. Layers one and two are content inspection and destination
 * control; both are probabilistic. This one is deliberate policy: certain tool
 * calls have consequences that no scanner should be allowed to authorise on the
 * model's behalf.
 *
 * The reasoning is Meta's "Rule of Two" for agent design: an agent may combine
 * at most two of (a) processing untrusted input, (b) access to sensitive
 * systems, (c) changing state externally. An MCP agent reading tool results is
 * permanently in possession of (a). So any call that is both sensitive and
 * state-changing is asking for all three at once — and that is exactly the shape
 * of every real-world agent incident.
 *
 * This module does not try to be clever. It classifies the call and, when the
 * class is consequential, requires that a human or a policy have already said
 * yes. Deterministic, auditable, and outside the model's control.
 *
 * @typedef {'allow'|'confirm'|'block'} ActionVerdictKind
 */

/**
 * @typedef {object} ActionRule
 * @property {string} id
 * @property {ActionVerdictKind} verdict
 * @property {string} reason
 * @property {RegExp} [tool]        Match the tool name.
 * @property {RegExp} [arg]         Match the serialized arguments.
 */

/**
 * Argument text is inspected in serialized form, so a bare `rm -rf /` arrives
 * as `{"command":"rm -rf /"}`. Any end-of-token assertion must therefore accept
 * JSON structural characters as well as shell ones, or the rule silently misses
 * every structured call — the exact bug this constant exists to prevent.
 */
const TOKEN_END = String.raw`(?:\s|$|["'\]},;|&]|\\)`;

/**
 * Ordered: the first matching rule wins.
 *
 * ORDERING IS SECURITY-CRITICAL. Block rules are evaluated before confirm
 * rules, and argument-based rules before tool-name-based rules. Otherwise a
 * generic `run_shell -> confirm` rule shadows the far more specific
 * `rm -rf / -> block` rule, and a destructive command is downgraded to a
 * question. Specific and severe first; general and mild last.
 *
 * @type {ActionRule[]}
 */
export const ACTION_RULES = [
  // ---- Block: argument-level. Checked first, because the tool name is far
  //      less informative than what the call actually does. ---------------
  {
    id: "ACT-BLOCK-01",
    verdict: "block",
    arg: new RegExp(
      String.raw`\brm\s+-[a-z]*[rf][a-z]*\s+(?:--no-preserve-root\s+)?(?:/|/\*|~|\$HOME)` + TOKEN_END,
      "i",
    ),
    reason: "recursive delete of a root or home path",
  },
  {
    id: "ACT-BLOCK-02",
    verdict: "block",
    arg: /\b(?:curl|wget)\b[^|\n]{0,150}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/i,
    reason: "pipe-to-shell: remote code execution with no review step",
  },
  {
    id: "ACT-BLOCK-03",
    verdict: "block",
    arg: /\b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\b|\bDELETE\s+FROM\s+\w+\s*(?:;|"|$)/i,
    reason: "irreversible data destruction",
  },
  {
    id: "ACT-BLOCK-04",
    verdict: "block",
    arg: /\b(?:mkfs(?:\.\w+)?|dd)\b[^.\n]{0,40}of=\/dev\/|\bchmod\s+(?:-R\s+)?777\s+\/|\:\s*\(\s*\)\s*\{\s*\:\s*\|\s*\:\s*&\s*\}\s*;/i,
    reason: "disk-destroying or fork-bombing command",
  },
  {
    id: "ACT-BLOCK-05",
    verdict: "block",
    arg: /169\.254\.169\.254|metadata\.google\.internal/i,
    reason: "attempt to reach cloud instance metadata",
  },

  // ---- Block: tool-name-level -------------------------------------------
  {
    id: "ACT-BLOCK-10",
    verdict: "block",
    tool: /^(?:delete|drop|truncate|purge|wipe|nuke)(?:[_-]|$)/i,
    reason: "irreversible destructive operation",
  },

  // ---- Confirm: argument-level ------------------------------------------
  {
    id: "ACT-CONFIRM-01",
    verdict: "confirm",
    arg: /\b(?:git\s+push|npm\s+publish|docker\s+push|kubectl\s+(?:apply|delete)|terraform\s+apply)\b/i,
    reason: "irreversible release or infrastructure change",
  },
  {
    id: "ACT-CONFIRM-02",
    verdict: "confirm",
    arg: /(?:~\/\.ssh|\.ssh\/id_(?:rsa|ed25519)|\.aws\/credentials|\.git-credentials|\.netrc)\b/i,
    reason: "touches long-lived credential material",
  },

  // ---- Confirm: tool-name-level. Last, because a name alone is weak
  //      evidence and must never shadow a stronger argument signal. -------
  {
    id: "ACT-CONFIRM-10",
    verdict: "confirm",
    tool: /(?:^|_)(?:exec|execute|shell|bash|cmd|command|spawn|run)(?:_|$)/i,
    reason: "arbitrary command execution",
  },
  {
    id: "ACT-CONFIRM-11",
    verdict: "confirm",
    tool: /(?:^|_)(?:write|create|edit|patch|modify|update|delete|remove|move|rename)(?:_|$)/i,
    reason: "mutates files or state",
  },
  {
    id: "ACT-CONFIRM-12",
    verdict: "confirm",
    tool: /(?:^|_)(?:post|put|patch|send|publish|upload|push|deploy|submit)(?:_|$)/i,
    reason: "changes state on a remote system",
  },
  {
    id: "ACT-CONFIRM-13",
    verdict: "confirm",
    tool: /(?:^|_)(?:payment|pay|transfer|withdraw|purchase|order|trade|swap)(?:_|$)/i,
    reason: "moves money or value",
  },
];

/**
 * @typedef {object} ActionVerdict
 * @property {ActionVerdictKind} verdict
 * @property {string} ruleId
 * @property {string} reason
 * @property {string} tool
 */

/**
 * Classify one outbound tool call.
 *
 * A rule with both `tool` and `arg` requires both to match; a rule with only one
 * requires that one. Rules are evaluated in order and the first match returns.
 *
 * @param {{tool:string, args:unknown}} call
 * @returns {ActionVerdict|null} null when nothing consequential is happening
 */
export function classifyCall(call) {
  const tool = call.tool || "";
  let args = "";
  try {
    args = typeof call.args === "string" ? call.args : JSON.stringify(call.args ?? "");
  } catch {
    args = "";
  }
  const haystack = `${tool} ${args}`;

  for (const rule of ACTION_RULES) {
    const toolOk = rule.tool ? rule.tool.test(tool) : false;
    const argOk = rule.arg ? rule.arg.test(haystack) : false;
    const matched = rule.tool && rule.arg ? toolOk && argOk : rule.tool ? toolOk : argOk;
    if (!matched) continue;
    return { verdict: rule.verdict, ruleId: rule.id, reason: rule.reason, tool };
  }
  return null;
}

/**
 * Whether a tool name is in the user's explicit "never ask" set.
 * @param {string} tool
 * @param {string[]} trustlist
 */
export function isTrustlisted(tool, trustlist) {
  if (!trustlist || trustlist.length === 0) return false;
  return trustlist.some((t) => t.toLowerCase() === tool.toLowerCase());
}

/**
 * Build the JSON-RPC error used when a call is refused at the action layer.
 * Kept distinct from the content-layer code so a client can tell the two apart.
 * @param {any} msg
 * @param {ActionVerdict} verdict
 */
export function actionDenial(msg, verdict) {
  return {
    jsonrpc: "2.0",
    id: msg.id === undefined ? null : msg.id,
    error: {
      code: -32002,
      message:
        `mcp-output-firewall: action blocked (${verdict.ruleId}) — ` +
        `${verdict.tool}: ${verdict.reason}. ` +
        `Add it to --trust-tools if this call was intended.`,
      data: {
        blockedBy: "mcp-output-firewall",
        layer: "action",
        ruleId: verdict.ruleId,
        tool: verdict.tool,
        reason: verdict.reason,
      },
    },
  };
}

/**
 * Build the JSON-RPC error used when a call needs confirmation but the proxy is
 * running unattended (no interactive approver available).
 * @param {any} msg
 * @param {ActionVerdict} verdict
 */
export function confirmationRequired(msg, verdict) {
  return {
    jsonrpc: "2.0",
    id: msg.id === undefined ? null : msg.id,
    error: {
      code: -32003,
      message:
        `mcp-output-firewall: confirmation required (${verdict.ruleId}) — ` +
        `${verdict.tool}: ${verdict.reason}. ` +
        `Run interactively to approve, or add the tool to --trust-tools.`,
      data: {
        blockedBy: "mcp-output-firewall",
        layer: "action",
        ruleId: verdict.ruleId,
        tool: verdict.tool,
        reason: verdict.reason,
        needsConfirmation: true,
      },
    },
  };
}
