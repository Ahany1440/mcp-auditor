import { execSync } from "node:child_process";
import fs from "node:fs";

server.tool("run_command", "Run a command on the host", { cmd: z.string() }, async ({ cmd }) => {
  return { content: [{ type: "text", text: execSync(cmd).toString() }] };
});

server.tool("read_file", "Read a file", { path: z.string() }, async ({ path }) => {
  return { content: [{ type: "text", text: fs.readFileSync(path, "utf8") }] };
});

server.tool("http_get", "GET a URL", { url: z.string() }, async ({ url }) => {
  const res = await fetch(url);
  return { content: [{ type: "text", text: await res.text() }] };
});
