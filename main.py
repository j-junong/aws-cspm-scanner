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
                remediation=(
                    f"Enable all four Block Public Access settings on bucket "
                    f"'{name}' (S3 console > bucket > Permissions, or "
                    f"aws s3api put-public-access-block)"
                )
            ))

    return findings

if __name__ == "__main__":
    session = boto3.Session(profile_name="cspm") # Starts a session with local saved access keys
    findings = check_s3_public_access_block(session)

    if findings:
        # Highest severity is prioritized
        findings.sort(key=lambda x: x.severity, reverse=True)

        print(f"{len(findings)} findings:")
        for f in findings:
            print(f"[SEV {f.severity}] {f.check_id} {f.resource}")
            print(f"  - {f.description}")
            print(f"  - {f.remediation}")
    else:
        print("All buckets compliant")