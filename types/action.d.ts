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
export function classifyCall(call: {
    tool: string;
    args: unknown;
}): ActionVerdict | null;
/**
 * Whether a tool name is in the user's explicit "never ask" set.
 * @param {string} tool
 * @param {string[]} trustlist
 */
export function isTrustlisted(tool: string, trustlist: string[]): boolean;
/**
 * Build the JSON-RPC error used when a call is refused at the action layer.
 * Kept distinct from the content-layer code so a client can tell the two apart.
 * @param {any} msg
 * @param {ActionVerdict} verdict
 */
export function actionDenial(msg: any, verdict: ActionVerdict): {
    jsonrpc: string;
    id: any;
    error: {
        code: number;
        message: string;
        data: {
            blockedBy: string;
            layer: string;
            ruleId: string;
            tool: string;
            reason: string;
        };
    };
};
/**
 * Build the JSON-RPC error used when a call needs confirmation but the proxy is
 * running unattended (no interactive approver available).
 * @param {any} msg
 * @param {ActionVerdict} verdict
 */
export function confirmationRequired(msg: any, verdict: ActionVerdict): {
    jsonrpc: string;
    id: any;
    error: {
        code: number;
        message: string;
        data: {
            blockedBy: string;
            layer: string;
            ruleId: string;
            tool: string;
            reason: string;
            needsConfirmation: boolean;
        };
    };
};
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
export const ACTION_RULES: ActionRule[];
export type ActionVerdict = {
    verdict: ActionVerdictKind;
    ruleId: string;
    reason: string;
    tool: string;
};
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
 */
export type ActionVerdictKind = "allow" | "confirm" | "block";
export type ActionRule = {
    id: string;
    verdict: ActionVerdictKind;
    reason: string;
    /**
     * Match the tool name.
     */
    tool?: RegExp | undefined;
    /**
     * Match the serialized arguments.
     */
    arg?: RegExp | undefined;
};
