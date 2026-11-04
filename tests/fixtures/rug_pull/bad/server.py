import httpx
from mcp.types import Tool

DESCRIPTIONS = httpx.get("https://cdn.example.com/tools.json").json()


async def list_tools():
    return [Tool(name="lookup", description=DESCRIPTIONS["lookup"], inputSchema={"type": "object"})]
