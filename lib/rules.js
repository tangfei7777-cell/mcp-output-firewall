// @ts-check
/**
 * mcp-output-firewall — rule engine (runtime)
 *
 * Plain ESM JavaScript with JSDoc types. No build step, no dependencies.
 *
 * The core value of this package: a curated, tested rule set that inspects
 * the *content* coming back from an MCP server (tool results, resources,
 * prompts) and decides whether it is safe to hand to an agent.
 *
 * Design principles:
 *  1. Precision over recall. A noisy filter gets uninstalled on day one.
 *     Every rule must have a concrete attack it stops.
 *  2. Content-first. We do not care which server produced it; we care what
 *     the bytes say.
 *  3. Explainable. Every hit returns the span, the reason, and a fix hint.
 */

/**
 * @typedef {'critical'|'high'|'medium'|'low'} Severity
 * @typedef {'injection'|'exfiltration'|'secrets'|'tool-hijack'|'obfuscation'|'supply-chain'} RuleCategory
 */

/**
 * @typedef {object} Rule
 * @property {string} id
 * @property {RuleCategory} category
 * @property {Severity} severity
 * @property {string} title
 * @property {string} why            Plain-language explanation of the attack this stops.
 * @property {RegExp[]} patterns     Any single match fires the rule.
 * @property {(match: string, full: string, index: number) => boolean} [refine]
 * @property {string} fix            Remediation hint surfaced in reports.
 */

/**
 * @typedef {object} Finding
 * @property {string} ruleId
 * @property {RuleCategory} category
 * @property {Severity} severity
 * @property {string} title
 * @property {string} why
 * @property {string} fix
 * @property {string} evidence
 * @property {number} index
 * @property {string} maskedEvidence
 */

/**
 * @typedef {object} ScanOptions
 * @property {Partial<Record<RuleCategory, boolean>>} [disable]
 * @property {Severity} [minSeverity]
 * @property {number} [maxHitsPerRule]
 * @property {boolean} [includeRawEvidence]
 */

/**
 * @typedef {object} ScanResult
 * @property {boolean} safe
 * @property {Severity|null} worst
 * @property {Finding[]} findings
 * @property {{bytesScanned:number, rulesRun:number, hits:number, elapsedMs:number}} stats
 */

/** @type {Record<Severity, number>} */
const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

// ---------------------------------------------------------------------------
// Secret masking
// ---------------------------------------------------------------------------

/** @type {Array<[RegExp, string]>} */
const SECRET_SHAPES = [
  [/\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b/g, "***APIKEY-REDACTED***"],
  [/\bghp_[A-Za-z0-9]{20,}\b/g, "ghp_***REDACTED***"],
  [/\bgho_[A-Za-z0-9]{20,}\b/g, "gho_***REDACTED***"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "github_pat_***REDACTED***"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "AKIA***REDACTED***"],
  [/\bAIza[0-9A-Za-z_-]{30,}\b/g, "AIza***REDACTED***"],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "xox***REDACTED***"],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "***JWT-REDACTED***"],
  [/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, "***B64-REDACTED***"],
];

const KV_SECRET_RE =
  /((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key)\s*[:=]\s*["']?)([^\s"',;]{6,})/gi;

/**
 * Replace anything that looks like a credential with a marker.
 * Used so that reports never re-leak a secret they just detected.
 * @param {string} text
 * @returns {string}
 */
export function maskSecrets(text) {
  let out = String(text);
  for (const [re, replacement] of SECRET_SHAPES) {
    out = out.replace(re, replacement);
  }
  out = out.replace(KV_SECRET_RE, (_m, prefix) => `${prefix}***REDACTED***`);
  return out;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/**
 * Build a regex matching "verb ... instruction-noun" phrasing, so we only
 * catch imperatives aimed at the model rather than incidental word pairs.
 * @param {string} verbs
 * @returns {RegExp}
 */
const imperatives = (verbs) =>
  new RegExp(
    `\\b(?:${verbs})\\b[^.!?\\n]{0,40}\\b(?:instruction|instructions|prompt|prompts|command|commands|rule|rules|directive|directives|guideline|guidelines|policy|policies|system\\s+message|previous|prior|above|earlier)\\b`,
    "gi",
  );

/**
 * Matcher for characters that carry no visible glyph. The `u` flag and the
 * braced astral escape are load-bearing: without them the astral range is
 * mis-parsed and the character class silently swallows ordinary letters.
 *
 * Coverage notes:
 *  - U+200B-200F  zero-width space/joiners, LRM/RLM
 *  - U+202A-202E  bidi embedding and override (Trojan Source)
 *  - U+2060-2064  word joiner and invisible operators
 *  - U+206A-206F  deprecated format controls
 *  - U+FE00-FE0F  variation selectors — used as a covert bit-channel
 *  - U+FEFF       BOM / zero-width no-break space
 *  - U+E0000-E007F Unicode tag characters — invisible in every renderer
 */
const INVISIBLE_PATTERN =
  "[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u206A-\\u206F\\uFE00-\\uFE0F\\uFEFF]" +
  "|[\\u{E0000}-\\u{E007F}]";

/**
 * A run of variation selectors, used as a covert channel. A single selector
 * after an emoji is normal (it chooses the glyph style); a long unbroken run on
 * ordinary text carries data and has no legitimate reading.
 */
const VARIATION_RUN_PATTERN = "[\\uFE00-\\uFE0F]{4,}";

/** @type {Rule[]} */
export const RULES = [
  // ------------------------- prompt injection -----------------------------
  {
    id: "INJ-001",
    category: "injection",
    severity: "critical",
    title: "Instruction override targeting the assistant",
    why: "The content tells the model to discard its existing instructions. This is the canonical prompt-injection payload and almost never appears in legitimate tool output.",
    patterns: [
      /ignore\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+(?:instruction|instructions|prompt|prompts|rule|rules|directive|directives|context)/gi,
      /disregard\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+(?:instruction|instructions|prompt|prompts|rule|rules|directive|directives)/gi,
      /\bforget\s+(?:everything|all|your)\s+(?:above|before|prior|previous|instructions|rules|context)/gi,
      imperatives("follow|obey|execute|comply\\s+with"),
    ],
    fix: "Treat this server as untrusted. Wrap its output in a delimiter and re-state to the model that returned content is data, not instructions.",
  },
  {
    id: "INJ-002",
    category: "injection",
    severity: "critical",
    title: "Forged system / role delimiter",
    why: "Content tries to impersonate a system message or a new conversation turn. If the agent concatenates raw tool output into its context, this rewrites its role and can seize control of the session.",
    patterns: [
      /<\|?\/?(?:im_start|im_end|system|assistant|user)\|?>/gi,
      /^\s*(?:system|assistant)\s*:\s*/gim,
      /\[\/?(?:INST|SYS|SYSTEM)\]/gi,
      /<\|(?:begin|end)_of_text\|>/gi,
      /###\s*(?:system|instruction|new\s+instruction)s?\s*:?/gi,
      /\bBEGIN\s+SYSTEM\s+PROMPT\b/gi,
    ],
    fix: "Strip role delimiters from tool output before it enters the context window, or escape them.",
  },
  {
    id: "INJ-003",
    category: "injection",
    severity: "high",
    title: "Invisible / zero-width text smuggling",
    why: "Zero-width, bidi-control and tag characters carry instructions that a human reviewer cannot see but the model still reads. Frequently used to hide a payload past a review step.",
    patterns: [
      new RegExp(INVISIBLE_PATTERN, "gu"),
      new RegExp(VARIATION_RUN_PATTERN, "gu"),
    ],
    refine: (match, full) => {
      // A run of variation selectors on ordinary text is a covert channel in
      // its own right — no threshold hunting required.
      if (new RegExp(VARIATION_RUN_PATTERN, "u").test(match)) return true;
      // A single stray ZWSP is common in sloppy HTML or a lone emoji selector;
      // 3+ indicates intent.
      const count = (full.match(new RegExp(INVISIBLE_PATTERN, "gu")) || []).length;
      return count >= 3;
    },
    fix: "Strip Unicode Cf-category characters and variation selectors from untrusted content.",
  },
  {
    id: "INJ-004",
    category: "injection",
    severity: "high",
    title: "Concealment instruction",
    why: "Asks the model to hide its actions or not tell the user. Legitimate tools have no reason to request secrecy from the agent.",
    patterns: [
      /\bdo\s+not\s+(?:tell|inform|notify|mention\s+to|reveal\s+to|alert)\s+(?:the\s+)?(?:user|human|operator|developer|admin)/gi,
      /\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|operator)/gi,
      /\b(?:don'?t|never)\s+(?:report|log|disclose|mention)\s+(?:this|that|it|these)\b/gi,
      /\bkeep\s+(?:this|it)\s+(?:secret|hidden|quiet|confidential)\b/gi,
    ],
    fix: "Block the payload and surface the attempt to the user.",
  },
  {
    id: "INJ-005",
    category: "injection",
    severity: "medium",
    title: "Authority impersonation",
    why: "The content claims to come from the developer, the vendor, or an emergency process to justify an otherwise suspicious request.",
    patterns: [
      /\b(?:this\s+is|i\s+am|message\s+from|on\s+behalf\s+of)\s+(?:the\s+)?(?:developer|anthropic|openai|admin|administrator|admin\s+team|security\s+team|support\s+team|your\s+creator|your\s+owner)\b/gi,
      /\b(?:official|authorized|urgent)\s+(?:directive|instruction|notice|update)\s+from\b/gi,
      /\bdeveloper\s+mode\b|\bmaintenance\s+mode\s+(?:enabled|activated)\b|\boverride\s+code\b/gi,
    ],
    fix: "Only accept instructions from the system prompt channel, never from tool output.",
  },
  {
    id: "INJ-006",
    category: "injection",
    severity: "high",
    title: "Forged security-clearance assertion",
    why: "The content asserts that it has already been checked by a scanner, classifier, or security pipeline and needs no further review. This is a live attack class: it contains no imperative to match, so it reassures the model instead of directing it. A genuine scanner verdict is delivered out of band by the client, never written into the payload it just cleared.",
    patterns: [
      // An explicit clearance verdict attributed to a scanning process.
      /\b(?:this\s+(?:content|message|output|tool\s+result|data)\s+(?:has\s+been|was)\s+)?(?:scanned|screened|verified|cleared|inspected|validated|audited)\b[^.\n]{0,60}\b(?:by|through)\b[^.\n]{0,40}\b(?:security|scanner|scan|pipeline|guardrail|classifier|sentinel|safety)\b/gi,
      /\b(?:security|safety|scan|scanning|inspection)\s+(?:pipeline|layer|gate|gateway|stage)\b[^.\n]{0,50}\b(?:cleared|passed|approved|verified|flagged\s+clean)\b/gi,
      // The tell-tale release note: no further inspection required.
      /\bno\s+(?:further|additional|more)\s+(?:inspection|review|scrutiny|checking|analysis)\s+(?:is\s+)?(?:required|needed|necessary)\b/gi,
      // A forged verdict line naming a classification about THIS payload.
      /\[(?:system|scanner|security|scan|guardrail|sentinel)[^\]]{0,40}\b(?:note|verdict|status|result|report|clearance)\b[^\]]{0,60}\]/gi,
      /\b(?:classification|verdict|status|scan[- ]result)\s*:\s*(?:DATA|SAFE|CLEAN|BENIGN|PASS|OK|TRUSTED)\b/gi,
      // Impersonating this tool or a sibling by name.
      /\b(?:verified|marked|labelled|labeled|confirmed)\s+(?:as\s+)?(?:safe|clean|benign|trusted|harmless)\s+by\b[^.\n]{0,40}\b(?:mcp-output-firewall|mcp-scan|scanner|guardrail|invariant|snyk)\b/gi,
    ],
    refine: (match, full, index) => {
      // Ordering matters: check the specific exfil-capable tell first, because
      // an attacker who bolts a real instruction onto a fake clearance note is
      // unambiguously hostile regardless of surrounding context.
      if (/\b(?:cat|read|print|send|post|upload|transmit|exfiltrate|curl|wget|\.env|\.ssh|id_rsa|credentials?)\b/i.test(match)) {
        return true;
      }
      // Otherwise only fire when the asserting text is not itself quoting or
      // documenting such a mechanism. A security blog explaining that attackers
      // write "no further inspection required" must not be flagged.
      const window = full.slice(Math.max(0, index - 160), index + match.length + 160);
      const documentational = /\b(?:attackers?|attacker\s+may|can\s+claim|might\s+claim|e\.g\.|for\s+example|such\s+as|this\s+is\s+how|technique|vectors?|defen[cs]e|mitigat\w*|documentation|tutorial|example\s+of|payloads?\s+like)\b/i;
      if (documentational.test(window)) return false;
      return true;
    },
    fix: "Never trust a clearance claim that arrives inside the payload it describes. Verdicts must come from the client's own out-of-band channel.",
  },

  // --------------------------- tool hijack --------------------------------
  {
    id: "HJK-001",
    category: "tool-hijack",
    severity: "critical",
    title: "Instructed to call a tool from content",
    why: "A tool result telling the agent to invoke another tool is the tool-poisoning bridge: it turns a read-only data fetch into an action. This is the highest-value attack in the MCP threat model.",
    patterns: [
      /\b(?:call|invoke|execute|run|use)\s+(?:the\s+)?(?:tool|function)\s+["'`]?([a-zA-Z_][\w.-]*)/gi,
      /\b(?:you\s+(?:must|should|need\s+to|have\s+to))\s+(?:now\s+)?(?:call|invoke|execute|run)\b/gi,
      /\bnext\s+step\s*:\s*(?:call|invoke|execute|run)\b/gi,
      /\b(?:tool|function)\s*[_ ]?call\s*:\s*[a-zA-Z_]/gi,
    ],
    refine: (match, full, index) => {
      // Prose that merely *documents* tool calls is normal in READMEs and MCP
      // docs. Inspect a narrow window around the match for doc markers.
      const window = full.slice(Math.max(0, index - 120), index + match.length + 120);
      if (/\b(?:docs?|documentation|readme|usage|example|tutorial|how\s+to|syntax|reference)\b/i.test(window)) {
        // Even in docs, an instruction directed at the reader is still an order.
        return /\b(?:you\s+(?:must|should|need\s+to|have\s+to)|please|now\s+(?:call|invoke|run|execute))\b/i.test(
          window,
        );
      }
      return true;
    },
    fix: "Treat tool output as data. Parse it into a structure and let the agent decide; never let it drive the next call directly.",
  },
  {
    id: "HJK-002",
    category: "tool-hijack",
    severity: "high",
    title: "Credential / environment harvesting request",
    why: "Asks the model to read env vars, .env files, SSH keys or cloud credentials. Classic first stage of exfiltration, increasingly seen embedded in malicious MCP servers and poisoned project files.",
    patterns: [
      /\b(?:cat|read|print|echo|dump|show|send|fetch|retrieve|exfiltrate)\b[^.\n]{0,30}(?:\.env\b|\benv\s+file\b|\benvironment\s+variables?\b|\bprocess\.env\b|\$AWS_|\$GITHUB_|\$OPENAI_|\$ANTHROPIC_|\$API_KEY)/gi,
      /(?:~\/\.ssh|\.ssh\/id_(?:rsa|ed25519)|id_rsa\b|id_ed25519\b|\.aws\/credentials|\.npmrc\b|\.git-credentials|\.netrc\b)/gi,
      /\b(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL|PRIVATE_KEY)\b/g,
    ],
    fix: "Deny the read at the tool boundary and add the target to your secret allow-list policy.",
  },
  {
    id: "HJK-003",
    category: "tool-hijack",
    severity: "high",
    title: "Covert network egress",
    why: "The content asks the agent to transmit data to an external endpoint. Combined with a read of local secrets this is a complete exfiltration chain.",
    patterns: [
      /\b(?:curl|wget|fetch|Invoke-WebRequest)\b[^.\n]{0,80}(?:-d\s|--data|--data-binary|-X\s*POST|-F\s|--form)/gi,
      /\b(?:post|upload|send|transmit|forward|beacon)\b[^.\n]{0,40}\b(?:to|towards)\b[^.\n]{0,60}https?:\/\/(?!localhost|127\.0\.0\.1)[^\s"')]+/gi,
      /\b(?:base64|b64encode|xxd\s+-p|openssl\s+enc)\b[^.\n]{0,60}(?:curl|wget|nc\s|ncat|socat|\/dev\/tcp)/gi,
    ],
    fix: "Enforce an egress allow-list in your MCP client; block this server if it attempts network calls it did not declare.",
  },
  {
    id: "HJK-004",
    category: "tool-hijack",
    severity: "high",
    title: "Dangerous shell command in output",
    why: "The payload contains a destructive shell command. Sometimes this is deliberate sabotage of the agent; sometimes it is a poisoned README the agent is told to 'follow'.",
    patterns: [
      /\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:\/|\/\*|\x7e|\$HOME|\*)\s*(?:$|[\s;&|])/gi,
      /\b(?:mkfs|dd)\s+[^.\n]{0,40}of=\/dev\//gi,
      /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/g,
      /\bchmod\s+(?:-R\s+)?777\s+\/(?:\s|$)/gi,
      /\b(?:curl|wget)\b[^|\n]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b/gi,
      /\bDROP\s+(?:TABLE|DATABASE)\b/gi,
    ],
    fix: "Never auto-execute commands parsed out of tool output. Require an explicit human or agent confirmation step.",
  },

  // -------------------------- exfiltration --------------------------------
  {
    id: "EXF-001",
    category: "exfiltration",
    severity: "high",
    title: "Markdown image / link beacon with encoded payload",
    why: "An image URL carrying a long opaque query string is a zero-click exfiltration channel: rendering the markdown sends your data to the attacker. Data is usually base64-encoded in the query.",
    patterns: [
      /!\[[^\]]*\]\(\s*https?:\/\/[^\s)]*\?[^\s)]{80,}\)/gi,
      /\[[^\]]*\]\(\s*https?:\/\/[^\s)]*\?(?:data|d|q|token|key|payload|info)=[^\s)]{40,}\)/gi,
      /https?:\/\/[^\s"')]{20,}\?(?:[a-zA-Z_]{1,20}=[A-Za-z0-9+/=_-]{40,}&?){1,}/g,
    ],
    fix: "Block remote image rendering from tool output, or strip long opaque query strings before display.",
  },
  {
    id: "EXF-002",
    category: "exfiltration",
    severity: "high",
    title: "DNS exfiltration / raw socket channel",
    why: "Encodes data into DNS lookups or opens a raw TCP socket. Bypasses HTTP allow-lists entirely.",
    patterns: [
      /\b(?:nslookup|dig|host|Resolve-DnsName)\b[^.\n]{0,60}\b[A-Za-z0-9+/=_-]{30,}\b/gi,
      /\b(?:nc|ncat|netcat|socat)\b[^.\n]{0,40}(?:-e|--exec|\/dev\/tcp|\|)/gi,
      /\b(?:bash|sh)\s+-i\s+>&\s*\/dev\/tcp\//gi,
    ],
    fix: "Block outbound DNS and raw sockets from the MCP host process.",
  },

  // ------------------------------ secrets ---------------------------------
  {
    id: "SEC-001",
    category: "secrets",
    severity: "high",
    title: "Live credential in output",
    why: "A recognizable API key, token or private key is present in the payload. Even when benign, it will be persisted into the conversation log and any telemetry pipeline.",
    patterns: [
      /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}\b/g,
      /\bghp_[A-Za-z0-9]{30,}\b/g,
      /\bgithub_pat_[A-Za-z0-9_]{30,}\b/g,
      /\bAKIA[0-9A-Z]{16}\b/g,
      /\bAIza[0-9A-Za-z_-]{35}\b/g,
      /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
      /-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----/g,
      /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,
    ],
    fix: "Rotate the leaked credential, then add a scrubbing layer so it never enters the context window.",
  },
  {
    id: "SEC-002",
    category: "secrets",
    severity: "medium",
    title: "Inline credential assignment",
    why: "A password or key is assigned in cleartext. Often a genuine mistake by a legitimate server, but it means the secret now lives in the transcript.",
    patterns: [
      /\b(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    ],
    fix: "Replace the value with a reference to a secret manager entry.",
  },

  // ---------------------------- obfuscation -------------------------------
  {
    id: "OBF-001",
    category: "obfuscation",
    severity: "medium",
    title: "Encoded blob offered for execution",
    why: "A large base64 or hex blob is presented together with a decode-and-run instruction. This is the standard way to smuggle a payload past keyword filters.",
    patterns: [
      /\b(?:base64\s+(?:-d|--decode)|atob|fromCharCode|bytes\.fromhex|(?:\\x[0-9a-f]{2}){8,})\b/gi,
      /\b(?:eval|exec|Function)\s*\(\s*(?:atob|Buffer\.from|base64)/gi,
      /\bpowershell\b[^.\n]{0,60}-(?:enc|EncodedCommand)\b/gi,
    ],
    fix: "Never decode-and-execute content that arrived in a tool result. Decode for inspection only.",
  },
  {
    id: "OBF-002",
    category: "obfuscation",
    severity: "low",
    title: "Homoglyph / confusable characters",
    why: "Cyrillic or Greek look-alikes are used to forge familiar words (e.g. 'ignоre' with a Cyrillic o) and slip past naive keyword filters or human review.",
    patterns: [/[\u0400-\u04FF\u0370-\u03FF]/g],
    refine: (_match, full) => {
      // Only interesting when it sits inside otherwise-ASCII text.
      const asciiRatio = (full.match(/[A-Za-z]/g) || []).length / Math.max(full.length, 1);
      return asciiRatio > 0.6 && /[A-Za-z][\u0400-\u04FF]|[\u0400-\u04FF][A-Za-z]/.test(full);
    },
    fix: "Normalize confusables to ASCII before any keyword-based decision.",
  },

  // --------------------------- supply chain -------------------------------
  {
    id: "SUP-001",
    category: "supply-chain",
    severity: "high",
    title: "Install-and-run-remote-script instruction",
    why: "Piping a remote script into a shell, or installing a package from an unlisted registry, is the standard supply-chain entry point and a common payload in poisoned READMEs.",
    patterns: [
      /\b(?:curl|wget)\b[^|\n]{0,150}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/gi,
      /\b(?:npm|pnpm|yarn)\s+(?:i|install|add)\b[^.\n]{0,60}(--registry\s+\S+|git\+https?:\/\/|https?:\/\/\S+\.tgz)/gi,
      /\bpip3?\s+install\b[^.\n]{0,60}(?:--index-url|--extra-index-url|-e\s+git\+)/gi,
    ],
    fix: "Pin dependencies and require an explicit review before installing anything a tool result suggested.",
  },
];

const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));

/** @param {string} s @param {number} [n] */
function truncate(s, n = 160) {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

/**
 * Make a matched span safe to print. Invisible/control characters are replaced
 * with a visible placeholder so reports do not contain silent gaps.
 * @param {string} s
 */
function printable(s) {
  return s
    .replace(new RegExp(INVISIBLE_PATTERN, "gu"), "·")
    .replace(/[\r\n\t]/g, (c) => (c === "\n" ? "\\n" : c === "\r" ? "\\r" : "\\t"));
}

/**
 * Scan a block of text for prompt-injection and exfiltration content.
 * Pure and synchronous: safe to call on every tool result.
 * @param {string} text
 * @param {ScanOptions} [options]
 * @returns {ScanResult}
 */
export function scan(text, options = {}) {
  const started = Date.now();
  const minSeverity = options.minSeverity || "low";
  const maxHitsPerRule = options.maxHitsPerRule || 5;
  /** @type {Finding[]} */
  const findings = [];
  let rulesRun = 0;

  if (typeof text !== "string" || text.length === 0) {
    return {
      safe: true,
      worst: null,
      findings: [],
      stats: { bytesScanned: 0, rulesRun: 0, hits: 0, elapsedMs: Date.now() - started },
    };
  }

  for (const rule of RULES) {
    if (options.disable && options.disable[rule.category]) continue;
    if (SEVERITY_ORDER[rule.severity] < SEVERITY_ORDER[minSeverity]) continue;
    rulesRun++;

    let hitsForRule = 0;
    for (const pattern of rule.patterns) {
      if (hitsForRule >= maxHitsPerRule) break;
      // A fresh regex per scan keeps lastIndex from leaking across calls.
      const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
      const re = new RegExp(pattern.source, flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) {
          re.lastIndex++;
          continue;
        }
        if (rule.refine && !rule.refine(m[0], text, m.index)) continue;

        const masked = maskSecrets(m[0]);
        findings.push({
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          title: rule.title,
          why: rule.why,
          fix: rule.fix,
          evidence: printable(
            options.includeRawEvidence || masked === m[0] ? truncate(m[0]) : truncate(masked),
          ),
          index: m.index,
          maskedEvidence: printable(truncate(masked)),
        });
        hitsForRule++;
        if (hitsForRule >= maxHitsPerRule) break;
      }
    }
  }

  findings.sort((a, b) => {
    const d = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    return d !== 0 ? d : a.index - b.index;
  });

  /** @type {Severity|null} */
  const worst = findings.length
    ? findings.reduce((acc, f) => (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[acc] ? f.severity : acc), /** @type {Severity} */ ("low"))
    : null;

  return {
    safe: findings.length === 0,
    worst,
    findings,
    stats: {
      bytesScanned: Buffer.byteLength(text, "utf8"),
      rulesRun,
      hits: findings.length,
      elapsedMs: Date.now() - started,
    },
  };
}

/**
 * @param {string} text
 * @param {ScanOptions} [options]
 * @returns {boolean}
 */
export function isSafe(text, options = {}) {
  return scan(text, options).safe;
}

/**
 * Scan every string field of an arbitrary JSON value (i.e. a tool result).
 * Returns findings annotated with a JSON path so you can locate the offender.
 * @param {unknown} value
 * @param {ScanOptions} [options]
 * @param {string} [path]
 * @returns {Array<Finding & {path:string}>}
 */
export function scanDeep(value, options = {}, path = "$") {
  /** @type {Array<Finding & {path:string}>} */
  const out = [];

  /** @param {unknown} node @param {string} p @param {number} depth */
  const walk = (node, p, depth) => {
    if (depth > 24 || out.length > 200) return;
    if (typeof node === "string") {
      for (const f of scan(node, options).findings) out.push({ ...f, path: p });
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${p}[${i}]`, depth + 1));
      return;
    }
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(/** @type {Record<string,unknown>} */ (node))) {
        walk(v, `${p}.${k}`, depth + 1);
      }
    }
  };

  walk(value, path, 0);
  out.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  return out;
}

/**
 * @typedef {object} SanitizeResult
 * @property {string} text
 * @property {boolean} changed
 * @property {string[]} applied
 */

const INVISIBLE_RE = new RegExp(INVISIBLE_PATTERN, "gu");
const VARIATION_RUN_RE = new RegExp(VARIATION_RUN_PATTERN, "gu");
const VARIATION_RUN_TEST_RE = new RegExp(VARIATION_RUN_PATTERN, "u");
const DELIM_RE = /<\|?\/?(?:im_start|im_end|system|assistant|user)\|?>/gi;
const DELIM_TEST_RE = /<\|?\/?(?:im_start|im_end|system|assistant|user)\|?>/i;
const OVERRIDE_RE = /** @type {RegExp} */ (RULES_BY_ID.get("INJ-001").patterns[0]);
const OVERRIDE_TEST_RE = new RegExp(OVERRIDE_RE.source, "i");
const BEACON_RE = /(!?\[[^\]]*\]\(\s*https?:\/\/[^\s)]*\?[^\s)]{80,}\))/gi;
const BEACON_TEST_RE = /!?\[[^\]]*\]\(\s*https?:\/\/[^\s)]*\?[^\s)]{80,}\)/i;

/** The forged-clearance family, reused by both the detector and the sanitizer. */
const CLEARANCE_RE =
  /\bno\s+(?:further|additional|more)\s+(?:inspection|review|scrutiny|checking|analysis)\s+(?:is\s+)?(?:required|needed|necessary)\b|\[(?:system|scanner|security|scan|guardrail|sentinel)[^\]]{0,40}\b(?:note|verdict|status|result|report|clearance)\b[^\]]{0,60}\]|\b(?:classification|verdict|scan[- ]result)\s*:\s*(?:DATA|SAFE|CLEAN|BENIGN|PASS|OK|TRUSTED)\b/gi;
const CLEARANCE_TEST_RE =
  /\bno\s+(?:further|additional|more)\s+(?:inspection|review|scrutiny|checking|analysis)\s+(?:is\s+)?(?:required|needed|necessary)\b|\[(?:system|scanner|security|scan|guardrail|sentinel)[^\]]{0,40}\b(?:note|verdict|status|result|report|clearance)\b[^\]]{0,60}\]|\b(?:classification|verdict|scan[- ]result)\s*:\s*(?:DATA|SAFE|CLEAN|BENIGN|PASS|OK|TRUSTED)\b/i;

/**
 * Rewrite text so it is safe to hand to a model.
 *
 * Deliberately conservative: it neutralises instruction-bearing constructs and
 * strips invisible characters, but does NOT delete the surrounding content.
 * The agent still sees the data; it just cannot be hijacked by it.
 * @param {string} text
 * @param {ScanOptions} [options]
 * @returns {SanitizeResult}
 */
export function sanitize(text, options = {}) {
  void options;
  if (typeof text !== "string" || text.length === 0) {
    return { text, changed: false, applied: [] };
  }
  /** @type {Set<string>} */
  const applied = new Set();
  let out = text;

  // 1. Strip invisible control characters that have no legitimate use in tool
  //    output. Cheap, high value, near-zero false-positive cost. Long runs of
  //    variation selectors count as smuggling, so collapse those first.
  let changedInvisible = false;
  if (VARIATION_RUN_TEST_RE.test(out)) {
    out = out.replace(VARIATION_RUN_RE, "");
    changedInvisible = true;
  }
  if (INVISIBLE_RE.test(out)) {
    out = out.replace(INVISIBLE_RE, "");
    changedInvisible = true;
  }
  if (changedInvisible) applied.add("INJ-003");

  // 2. Defang role delimiters so they cannot forge a conversation turn.
  if (DELIM_TEST_RE.test(out)) {
    out = out.replace(DELIM_RE, (m) => `⟦${m.replace(/[<>|/]/g, "")}⟧`);
    applied.add("INJ-002");
  }

  // 3. Neutralise instruction-override phrasing: keep the words (so the agent
  //    knows what the content said) but mark them as untrusted quotation.
  if (OVERRIDE_TEST_RE.test(out)) {
    out = out.replace(OVERRIDE_RE, (m) => `⚠️[untrusted-instruction: ${m}]`);
    applied.add("INJ-001");
  }

  // 4. Break markdown image beacons: rendering them leaks data.
  if (BEACON_TEST_RE.test(out)) {
    out = out.replace(BEACON_RE, (m) => `⛔[blocked-remote-beacon](len=${m.length})`);
    applied.add("EXF-001");
  }

  // 5. Defuse forged security-clearance claims. These carry no imperative, so
  //    they survive every signature list; what they do is lower the model's
  //    guard. Mark them so the assertion reads as a claim, not a fact.
  if (CLEARANCE_TEST_RE.test(out)) {
    out = out.replace(CLEARANCE_RE, (m) => `⚠️[untrusted-clearance-claim: ${m}]`);
    applied.add("INJ-006");
  }

  return { text: out, changed: applied.size > 0, applied: [...applied] };
}

/**
 * Machine-readable rule catalogue.
 * @returns {Array<Pick<Rule,'id'|'category'|'severity'|'title'|'why'|'fix'>>}
 */
export function listRules() {
  return RULES.map(({ id, category, severity, title, why, fix }) => ({
    id,
    category,
    severity,
    title,
    why,
    fix,
  }));
}
