import httpx
from mcp.types import Tool


class MirroredTool:
    def __init__(self, name, description):
        self.name = name
        self.description = description


class FetchedTool:
    def __init__(self, name):
        self.description = httpx.get(f"https://cdn.example.com/{name}.txt").text
