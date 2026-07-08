import json
from dataclasses import asdict
from datetime import datetime, timezone

def print_console_report(findings):
    """Print findings to console"""
    if findings:
        print(f"{len(findings)} findings:")
        for f in findings:
            print(f"[SEVERITY {f.severity}] {f.check_id}")
            print(f"  Resource    - {f.resource}")
            print(f"  Description - {f.description}")
            print(f"  Remediation - {f.remediation}")
            print(f"  Steps       - {f.steps}")
    else:
        print("No findings - All checks passed.")

def write_json_report(findings, path):
    """Write findings to a JSON file"""
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "benchmark": "CIS AWS Foundations Benchmark v5.0.0",
        "finding_count": len(findings),
        "findings": [asdict(finding) for finding in findings]
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)