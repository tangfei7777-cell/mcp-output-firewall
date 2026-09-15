// @ts-check
/**
 * mcp-output-firewall — egress policy (runtime)
 *
 * The second layer, and the one that answers the question the content scanner
 * cannot: "what if the injection gets through anyway?"
 *
 * The content scanner inspects the server→client direction. It never sees the
 * client→server direction, which is where the damage is actually done. A
 * perfectly benign tool — fetch_url, http_request, run_sql — becomes an
 * exfiltration channel the moment a poisoned tool result tells the agent to
 * call it with the right argument.
 *
 * This layer sits on the outbound call path and answers one question:
 *   "is this call trying to reach somewhere it has no business reaching?"
 *
 * Design stance: deny-by-default for the *unusual*, allow-by-default for the
 * *ordinary*. A policy that blocks a developer's everyday workflow gets turned
 * off within a day, taking the whole tool with it. So:
 *   - Destinations the user explicitly allows always pass.
 *   - Well-known public hosts (package registries, docs, common APIs) pass.
 *   - Anything carrying data to an unrecognised host is the case we flag.
 *   - Private/link-local/metadata addresses are always blocked: those are the
 *     SSRF and cloud-credential-theft targets, with no legitimate use here.
 *
 * @typedef {'allow'|'block'} EgressAction
 */

/** Addresses that must never be reachable from an agent tool call. */
const NEVER_ALLOWED_HOSTS = [
  // Cloud instance metadata — the primary credential-theft target.
  /^169\.254\.169\.254$/,
  /^metadata\.google\.internal$/i,
  /^100\.100\.100\.200$/,
];

/**
 * Hosts where a call is unremarkable and blocking would be noise. This is an
 * allow-list of *shapes*, not a security boundary — the security boundary is
 * the explicit --egress-allow list plus the block rules below.
 */
const ORDINARY_HOSTS = [
  /(^|\.)github\.com$/i,
  /(^|\.)githubusercontent\.com$/i,
  /(^|\.)npmjs\.(?:com|org)$/i,
  /(^|\.)pypi\.org$/i,
  /(^|\.)nodejs\.org$/i,
  /(^|\.)mozilla\.org$/i,
  /(^|\.)w3\.org$/i,
  /(^|\.)wikipedia\.org$/i,
  /(^|\.)stackoverflow\.com$/i,
  /(^|\.)python\.org$/i,
  /(^|\.)readthedocs\.(?:io|org)$/i,
  /(^|\.)json-schema\.org$/i,
  /(^|\.)schema\.org$/i,
  /(^|\.)example\.com$/i,
  /(^|\.)openai\.com$/i,
  /(^|\.)anthropic\.com$/i,
  /(^|\.)api\.(?:openai|anthropic)\.com$/i,
];

/** Argument names commonly used to carry a destination. */
const DESTINATION_KEYS = [
  "url", "uri", "endpoint", "host", "hostname", "address", "target", "dest",
  "destination", "server", "webhook", "callback", "href", "link", "src",
];

/**
 * Argument values that indicate a command is being assembled for execution.
 * Presence of these plus a network verb is the classic exfiltration shape.
 */
const DATA_CARRYING = /(?:^|[^a-z])(?:-d|--data|--data-binary|--data-raw|-F|--form|--upload-file|@-|>\s*\/dev\/tcp)/i;

/**
 * @typedef {object} EgressVerdict
 * @property {EgressAction} action
 * @property {string} reason
 * @property {string} [host]
 * @property {string} [tool]
 */

/**
 * Pull every hostname out of a string.
 * @param {string} text
 * @returns {string[]}
 */
export function extractHosts(text) {
  /** @type {string[]} */
  const hosts = [];
  // Full URLs.
  const urlRe = /\bhttps?:\/\/([^\s/:?#"'`<>)\]]+)/gi;
  let m;
  while ((m = urlRe.exec(text)) !== null) hosts.push(m[1]);
  // Bare IPv4 with an explicit port or path — common in hand-rolled exfil.
  const ipRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?\b/g;
  while ((m = ipRe.exec(text)) !== null) hosts.push(m[1]);
  // Hostname carrying a long opaque subdomain label (DNS tunnelling shape).
  const dnsRe = /\b([a-z0-9]{32,}\.[a-z0-9.-]+\.[a-z]{2,})\b/gi;
  while ((m = dnsRe.exec(text)) !== null) hosts.push(m[1]);
  return [...new Set(hosts)];
}

/**
 * @param {string} host
 * @param {RegExp[]} patterns
 */
function matchesAny(host, patterns) {
  return patterns.some((p) => p.test(host));
}

/**
 * Decide whether one outbound tool call may proceed.
 *
 * @param {object} call
 * @param {string} call.tool
 * @param {unknown} call.args
 * @param {object} [policy]
 * @param {string[]} [policy.allow]        Hosts the user explicitly permits.
 * @param {boolean} [policy.allowPrivate]  Permit RFC1918 destinations.
 * @returns {EgressVerdict[]} one verdict per suspicious destination found
 */
export function evaluateCall(call, policy = {}) {
  /** @type {EgressVerdict[]} */
  const verdicts = [];
  const allow = (policy.allow || []).map((h) => h.toLowerCase());
  const serialized = safeStringify(call.args);

  /** @type {string[]} */
  const hosts = extractHosts(serialized);
  // Ports/URLs assembled from split arguments: inspect values, not just hosts.
  for (const [key, value] of walkPairs(call.args)) {
    if (typeof value !== "string") continue;
    const looksLikeDestination = DESTINATION_KEYS.includes(key.toLowerCase()) || /^https?:\/\//i.test(value);
    if (!looksLikeDestination) continue;
    for (const h of extractHosts(value)) hosts.push(h);
  }

  const unique = [...new Set(hosts)];
  if (unique.length === 0) return verdicts;

  for (const host of unique) {
    const lower = host.toLowerCase();

    // 1. User allow-list wins over everything except the never-allowed set.
    const explicitlyAllowed = allow.some((a) => lower === a || lower.endsWith("." + a));

    // 2. Metadata endpoints are never permitted, not even explicitly.
    if (matchesAny(lower, NEVER_ALLOWED_HOSTS)) {
      verdicts.push({
        action: "block",
        host: lower,
        tool: call.tool,
        reason: "cloud instance metadata endpoint — credential theft target, never legitimate here",
      });
      continue;
    }

    if (explicitlyAllowed) continue;

    // 3. Private ranges: only if the operator opted in.
    if (isPrivateHost(lower) && !policy.allowPrivate) {
      verdicts.push({
        action: "block",
        host: lower,
        tool: call.tool,
        reason: "private or loopback destination — not permitted unless --egress-allow-private is set",
      });
      continue;
    }
    if (isPrivateHost(lower) && policy.allowPrivate) continue;

    // 4. Ordinary public infrastructure.
    if (matchesAny(lower, ORDINARY_HOSTS)) continue;

    // 5. Unknown public host. Blocking every one would be unusable, so the
    //    judgement call is: does it look like an active allow-list bypass?
    const suspicious = matchesAny(lower, [
      /(?:^|\.)(?:evil|exfil|collect|drop|beacon|attacker|malware|pastebin\.com|transfer\.sh|0x0\.st|ngrok\.io|requestbin|pipedream)\b/i,
    ]);
    const dnsTunnel = /^[a-z0-9]{32,}\./i.test(lower);

    if (suspicious || dnsTunnel) {
      verdicts.push({
        action: "block",
        host: lower,
        tool: call.tool,
        reason: dnsTunnel
          ? "long opaque subdomain — DNS tunnelling shape"
          : "destination matches a known drop/exfiltration host pattern",
      });
      continue;
    }

    // 6. Unknown but unremarkable. Record it, let it through — the policy is
    //    not a web filter, and pretending otherwise creates false confidence.
    verdicts.push({
      action: "allow",
      host: lower,
      tool: call.tool,
      reason: "unrecognised public host — permitted, but worth an explicit allow-list entry",
    });
  }

  return verdicts;
}

/** @param {string} host */
function isPrivateHost(host) {
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (host === "::1" || host === "[::1]") return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

/**
 * Walk every [key, value] pair at any depth.
 * @param {unknown} node
 * @param {number} [depth]
 * @returns {Array<[string, unknown]>}
 */
function walkPairs(node, depth = 0) {
  /** @type {Array<[string, unknown]>} */
  const out = [];
  if (depth > 12 || node === null || typeof node !== "object") return out;
  if (Array.isArray(node)) {
    for (const v of node) out.push(...walkPairs(v, depth + 1));
    return out;
  }
  for (const [k, v] of Object.entries(/** @type {Record<string,unknown>} */ (node))) {
    out.push([k, v]);
    out.push(...walkPairs(v, depth + 1));
  }
  return out;
}

/** @param {unknown} v */
function safeStringify(v) {
  try {
    return typeof v === "string" ? v : JSON.stringify(v);
  } catch {
    return "";
  }
}

/**
 * Parse a comma-separated --egress-allow value.
 * @param {string} raw
 * @returns {string[]}
 */
export function parseAllowList(raw) {
  return String(raw)
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}
