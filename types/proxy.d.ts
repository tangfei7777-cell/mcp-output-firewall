/**
 * Long-lived proxy entry point used by the CLI.
 * @param {any} options
 * @returns {SentryProxy}
 */
export function runProxy(options: any): SentryProxy;
export class SentryProxy extends EventEmitter<[never]> {
    /** @param {any} options */
    constructor(options: any);
    opts: any;
    /** @type {import('node:child_process').ChildProcessWithoutNullStreams|null} */
    child: import("node:child_process").ChildProcessWithoutNullStreams | null;
    stats: {
        inbound: number;
        outbound: number;
        findings: number;
        blocked: number;
        rewritten: number;
        errors: number;
        oversize: number;
        egressChecks: number;
        egressBlocks: number;
        actionChecks: number;
        actionBlocks: number;
    };
    getStats(): {
        inbound: number;
        outbound: number;
        findings: number;
        blocked: number;
        rewritten: number;
        errors: number;
        oversize: number;
        egressChecks: number;
        egressBlocks: number;
        actionChecks: number;
        actionBlocks: number;
    };
    /** Launch the upstream server and wire up the relay. */
    start(): void;
    clientToServer: import("readline").Interface | undefined;
    serverToClient: import("readline").Interface | undefined;
    stop(): void;
    /**
     * Write to the client, pausing the upstream read when stdout would queue.
     * @param {string} line
     */
    toClient(line: string): void;
    /**
     * Write to the upstream server, pausing the client read when its stdin
     * would queue.
     * @param {string} line
     */
    toServer(line: string): void;
    /**
     * Whether one message is over the inspection limit.
     * @param {string} line
     */
    oversize(line: string): boolean;
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
    inspectOutbound(msg: any): any | null;
    /**
     * @param {any} msg
     * @param {string} tool
     * @param {any[]} blocking
     */
    egressDenial(msg: any, tool: string, blocking: any[]): {
        jsonrpc: string;
        id: any;
        error: {
            code: number;
            message: string;
            data: {
                blockedBy: string;
                layer: string;
                tool: string;
                destinations: {
                    host: any;
                    reason: any;
                }[];
            };
        };
    };
    /** @param {string} text */
    log(text: string): void;
    /**
     * Build a JSON-RPC error to send in place of a poisoned result, so the
     * client fails loudly instead of silently consuming attacker-controlled data.
     * @param {any} msg
     * @param {any} inspected
     */
    denial(msg: any, inspected: any): {
        jsonrpc: string;
        id: any;
        error: {
            code: number;
            message: string;
            data: {
                blockedBy: string;
                worst: any;
                findings: any;
            };
        };
    };
    /**
     * Inspect one server→client message. Returns null when there is nothing
     * worth reporting (the common case, kept fast).
     * @param {any} msg
     * @returns {any|null}
     */
    inspect(msg: any): any | null;
}
export type ProxyMode = "monitor" | "warn" | "block";
export type Severity = import("./rules.js").Severity;
export type Finding = import("./rules.js").Finding;
import { EventEmitter } from "node:events";
