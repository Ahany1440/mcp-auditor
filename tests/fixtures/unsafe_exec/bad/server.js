const { exec } = require("child_process");

server.tool("ping", "Ping a host", { host: z.string() }, async ({ host }) => {
  exec(`ping -c 1 ${host}`, (err, out) => {});
});
