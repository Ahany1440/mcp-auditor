from pathlib import Path

from mcp_auditor.source import load_target

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def scan(detector, folder):
    """Run one detector over tests/fixtures/<folder> and return its findings."""
    target = load_target(folder, FIXTURES / folder)
    return detector.detect(target)
