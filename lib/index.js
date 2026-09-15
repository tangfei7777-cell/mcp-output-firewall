// @ts-check
/**
 * mcp-output-firewall — public API surface
 *
 * Three layers, exported separately so you can adopt one without the others:
 *   rules.js      layer 1 — content inspection (is this payload safe to read?)
 *   egress.js     layer 2 — destination policy (where is this call going?)
 *   action.js     layer 3 — action policy (should this call happen at all?)
 */

// ---- Layer 1: content -----------------------------------------------------
export {
  scan,
  scanDeep,
  sanitize,
  isSafe,
  listRules,
  maskSecrets,
  RULES,
} from "./rules.js";

// ---- Layer 2: egress ------------------------------------------------------
export { evaluateCall, extractHosts, parseAllowList } from "./egress.js";

// ---- Layer 3: action ------------------------------------------------------
export {
  classifyCall,
  isTrustlisted,
  actionDenial,
  confirmationRequired,
  ACTION_RULES,
} from "./action.js";

// ---- Proxy and reporting --------------------------------------------------
export { SentryProxy, runProxy } from "./proxy.js";

export { renderFindings, renderScanResult, toJsonReport, exitCodeFor } from "./report.js";

// ---- Adversarial benchmark ------------------------------------------------
export { ATTACK_VECTORS, summarizeByClass } from "./adversarial.js";
export { runBenchmark, renderBench, toJsonBench } from "./benchmark.js";
