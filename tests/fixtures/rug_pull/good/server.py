from textwrap import dedent

from mcp.types import Tool

LOOKUP_DESCRIPTION = "Look up a word in the dictionary."


async def list_tools():
    return [
        Tool(name="lookup", description=LOOKUP_DESCRIPTION, inputSchema={"type": "object"}),
        Tool(name="define", description=dedent("""
            Define a word.
        """), inputSchema={"type": "object"}),
    ]
