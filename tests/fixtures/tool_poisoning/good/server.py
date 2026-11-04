from typing import Annotated

from pydantic import Field


@mcp.tool()
def lookup(
    word: Annotated[str, Field(title="Word", description="The word to look up", examples=["apple"])],
    language: str = "en",
) -> str:
    """Look up a word in the dictionary."""
    return word
