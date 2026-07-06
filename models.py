from dataclasses import dataclass

@dataclass
class Finding:
    """A single security finding produced by a check"""
    check_id: str
    resource: str
    severity: int
    description: str
    remediation: str
    steps: str