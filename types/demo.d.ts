/**
 * mcp-output-firewall — built-in attack samples
 *
 * Real-world patterns observed in malicious MCP servers, poisoned README files
 * and tool-poisoning research. They serve three purposes:
 *   1. `mcp-output-firewall scan --demo` gives an immediate, honest signal of what the
 *      engine catches.
 *   2. The test suite asserts every one of these is caught.
 *   3. They double as documentation of the threat model.
 *
 * NOTE: all credentials below are obviously fake and non-functional.
 */
/** @typedef {'low'|'medium'|'high'|'critical'|'clean'} ExpectWorst */
/**
 * @typedef {object} DemoSample
 * @property {string} name
 * @property {string} scenario
 * @property {ExpectWorst} expectWorst
 * @property {string} content
 */
/** @type {DemoSample[]} */
export const DEMO_SAMPLES: DemoSample[];
/** Which sample each rule is expected to fire on. Asserted by the test suite. */
export const RULE_COVERAGE_EXPECTATIONS: {
    "INJ-001": string;
    "INJ-002": string;
    "INJ-003": string;
    "INJ-004": string;
    "INJ-005": string;
    "HJK-001": string;
    "HJK-002": string;
    "HJK-003": string;
    "HJK-004": string;
    "EXF-001": string;
    "SEC-001": string;
    "OBF-001": string;
    "SUP-001": string;
};
export type ExpectWorst = "low" | "medium" | "high" | "critical" | "clean";
export type DemoSample = {
    name: string;
    scenario: string;
    expectWorst: ExpectWorst;
    content: string;
};
