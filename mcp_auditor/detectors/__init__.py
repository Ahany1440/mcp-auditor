"""One module per detector. Each exposes RULE and detect(target) -> list[Finding]."""
from . import broad_capabilities, missing_auth, rug_pull, secrets, tool_poisoning, unsafe_exec

DETECTORS = [tool_poisoning, broad_capabilities, secrets, unsafe_exec, missing_auth, rug_pull]
RULES = [d.RULE for d in DETECTORS]


def run_all(target):
    from ..models import severity_rank
    findings = [f for d in DETECTORS for f in d.detect(target)]
    return sorted(findings, key=lambda f: (-severity_rank(f.severity), f.rule.id, f.file or "", f.line or 0))
