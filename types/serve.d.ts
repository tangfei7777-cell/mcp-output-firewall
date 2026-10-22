/**
 * Run the standalone MCP server over stdio until the client closes the stream.
 *
 * @param {object} [options]
 * @param {boolean} [options.quiet]  Suppress the startup line on stderr.
 * @returns {FirewallServer}
 */
export function runServe(options?: {
    quiet?: boolean | undefined;
}): FirewallServer;
export type Severity = "low" | "medium" | "high" | "critical";
declare class FirewallServer {
    /** @type {string} */
    era: string;
    /** @type {string|null} */
    negotiatedLegacyVersion: string | null;
    /**
     * Handle one parsed message. Notifications produce no output, which is the
     * whole difference between a notification and a request.
     * @param {any} msg
     */
    handle(msg: any): void;
    /**
     * @param {any} msg
     * @param {boolean} modern
     */
    dispatch(msg: any, modern: boolean): void;
    /**
     * @param {any} id
     * @param {any} params
     * @param {boolean} modern
     */
    callTool(id: any, params: any, modern: boolean): void;
}
export {};
