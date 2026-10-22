/**
 * Group vectors by attack class with per-class tallies.
 * @returns {Array<{attackClass:string, total:number, catchable:number, gaps:number, controls:number}>}
 */
export function summarizeByClass(): Array<{
    attackClass: string;
    total: number;
    catchable: number;
    gaps: number;
    controls: number;
}>;
/** @type {AttackVector[]} */
export const ATTACK_VECTORS: AttackVector[];
export type Expectation = "catch" | "gap" | "clean";
export type AttackVector = {
    id: string;
    /**
     * Grouping used for the published scorecard.
     */
    attackClass: string;
    title: string;
    /**
     * How the payload would arrive in real life.
     */
    vector: string;
    expected: Expectation;
    /**
     * Which defence layer handles it when the
     *    scanner does not (only for expected:"gap").
     */
    coveredBy?: string | undefined;
    content: string;
};
