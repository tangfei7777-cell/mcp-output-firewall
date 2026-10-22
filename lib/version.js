// @ts-check
/**
 * mcp-output-firewall — single source of truth for the tool version.
 *
 * The CLI banner, the JSON reports and the `serve` serverInfo all state a
 * version. Restating it in each place is how a package ends up claiming to
 * be three different versions at once, so every caller reads package.json.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));

/** @type {string|null} */
let cached = null;

/**
 * The package version, or "0.0.0" when package.json cannot be read (the
 * string is display metadata and must never be a crash).
 * @returns {string}
 */
export function readVersion() {
  if (cached !== null) return cached;
  try {
    const pkg = JSON.parse(readFileSync(join(HERE, "..", "package.json"), "utf8"));
    cached = typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    cached = "0.0.0";
  }
  return cached ?? "0.0.0";
}
