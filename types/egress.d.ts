/**
 * Pull every hostname out of a string.
 * @param {string} text
 * @returns {string[]}
 */
export function extractHosts(text: string): string[];
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
export function evaluateCall(call: {
    tool: string;
    args: unknown;
}, policy?: {
    allow?: string[] | undefined;
    allowPrivate?: boolean | undefined;
}): EgressVerdict[];
/**
 * Parse a comma-separated --egress-allow value.
 * @param {string} raw
 * @returns {string[]}
 */
export function parseAllowList(raw: string): string[];
export type EgressVerdict = {
    action: EgressAction;
    reason: string;
    host?: string | undefined;
    tool?: string | undefined;
};
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
 */
export type EgressAction = "allow" | "block";
