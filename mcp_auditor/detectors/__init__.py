"""One module per detector. Each exposes RULE and detect(target) -> list[Finding]."""
from ..remote import RULE as REMOTE_RULE
from . import broad_capabilities, missing_auth, rug_pull, secrets, tool_poisoning, unsafe_exec

DETECTORS = [tool_poisoning, broad_capabilities, secrets, unsafe_exec, missing_auth, rug_pull]
RULES = [d.RULE for d in DETECTORS] + [REMOTE_RULE]  # MCP007 runs from cli.py: it needs the network, not a Target


def run_all(target):
    return sort_findings([f for d in DETECTORS for f in d.detect(target)])


def sort_findings(findings):
    """Worst first, then by rule and location."""
    from ..models import severity_rank
    return sorted(findings, key=lambda f: (-severity_rank(f.severity), f.rule.id, f.file or "", f.line or 0))
