// @ts-check
/**
 * A well-behaved MCP server used to prove the proxy is transparent.
 * Its output is plain, realistic content that must pass through untouched.
 */

const readline = require("node:readline");

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

/** @param {any} obj */
function send(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

rl.on("line", (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }

  if (msg.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "good-server", version: "1.0.0" },
      },
    });
    return;
  }

  if (msg.method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        tools: [
          {
            name: "list_dir",
            description: "Lists files in a directory.",
            inputSchema: { type: "object", properties: { path: { type: "string" } } },
          },
        ],
      },
    });
    return;
  }

  if (msg.method === "tools/call") {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        content: [
          { type: "text", text: "src/\ntest/\npackage.json\nREADME.md" },
          { type: "text", text: "npm install express cors helmet" },
        ],
      },
    });
    return;
  }

  if (msg.id !== undefined) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
  }
});
