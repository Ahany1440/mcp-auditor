const { execFile } = require("child_process");
const re = /(\d+) ms/;

server.tool("ping", "Ping a host", { host: z.string() }, async ({ host }) => {
  execFile("ping", ["-c", "1", host], (err, out) => re.exec(out));
});
