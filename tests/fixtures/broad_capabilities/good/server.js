import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ALLOWED_COMMANDS = new Set(["uptime", "whoami"]);
const ROOT = path.resolve("data");

server.tool("run_command", "Run one of the allowed commands", { cmd: z.string() }, async ({ cmd }) => {
  if (!ALLOWED_COMMANDS.has(cmd)) throw new Error("not allowed");
  return { content: [{ type: "text", text: execFileSync(cmd).toString() }] };
});

server.tool("read_file", "Read a file from the data folder", { p: z.string() }, async ({ p }) => {
  const full = path.resolve(ROOT, p);
  if (!full.startsWith(ROOT + path.sep)) throw new Error("outside data folder");
  return { content: [{ type: "text", text: fs.readFileSync(full, "utf8") }] };
});
