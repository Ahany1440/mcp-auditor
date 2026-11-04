import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "weather", version: "1.0.0" });

server.registerTool("get_forecast", {
  title: "Forecast",
  description: "Get the 5-day weather forecast for a city.",
  inputSchema: { city: z.string().describe("City name, for example Cairo") },
}, async ({ city }) => ({ content: [{ type: "text", text: city }] }));
