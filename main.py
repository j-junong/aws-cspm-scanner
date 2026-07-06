import boto3

from models import Finding

def check_s3_public_access_block(session):
    """Check if bucket can be accessed by the public"""
    s3 = session.client("s3")
    findings = []

    for bucket in s3.list_buckets()["Buckets"]: # Lists individual existing buckets
        name = bucket["Name"]

        try:
            response = s3.get_public_access_block(Bucket=name)
            config = response["PublicAccessBlockConfiguration"]
            fully_blocked = all(config.values()) # True if all 4 configurations are ticked
        except s3.exceptions.ClientError as e: # Config does not exist will raise error
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                fully_blocked = False
            else:
                raise

        if not fully_blocked:
            findings.append(Finding(
                check_id="CIS-2.1.4",
                resource=name,
                severity=3,
                description=f"Bucket '{name}' does not block all public access.",
                remediation="Enable all four Block Public Access settings on bucket",
                steps=(
                    f"(Search Bar > S3 > Bucket > {name} > Permissions > "
                    "Block public access (bucket settings) > Edit > Tick Block all public access)"
                )
            ))

    return findings

def check_root_mfa(session):
    """Checks whether the root account has MFA enabled"""
    iam = session.client("iam")
    findings = []
    summary = iam.get_account_summary()["SummaryMap"]

    if not summary["AccountMFAEnabled"]: # 1 if enabled
        findings.append(Finding(
            check_id="CIS-1.4",
            resource="Root account",
            severity=4,
            description="Root account does not have MFA enabled.",
            remediation="Add MFA to your account",
            steps="(Search Bar > IAM > Security Recommendations > Add MFA)"
        ))

    return findings

if __name__ == "__main__":
    session = boto3.Session(profile_name="cspm") # Starts a session with local saved access keys
    findings = []
    findings += check_s3_public_access_block(session)
    findings += check_root_mfa(session)

    if findings:
        # Highest severity is prioritized
        findings.sort(key=lambda x: x.severity, reverse=True)

        print(f"{len(findings)} findings:")
        for f in findings:
            print(f"[SEV {f.severity}] {f.check_id} {f.resource}")
            print(f"  - {f.description}")
            print(f"  - {f.remediation}")
            print(f"  - {f.steps}")
    else:
        print("No findings - All checks passed.")