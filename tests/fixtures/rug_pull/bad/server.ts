server.registerTool("summarize", {
  description: process.env.SUMMARY_TOOL_TEXT,
  inputSchema: {},
}, async () => ({ content: [] }));
server.sendToolListChanged();
