import boto3
from moto.utilities import paginator
from requests import session

from models import Finding
from datetime import datetime, timezone

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
    summary = iam.get_account_summary()['SummaryMap']

    if not summary['AccountMFAEnabled']: # 1 if enabled
        findings.append(Finding(
            check_id="CIS-1.4",
            resource="Root account",
            severity=4,
            description="Root account does not have MFA enabled.",
            remediation="Add MFA to your account",
            steps="(Search Bar > IAM > Security Recommendations > Add MFA)"
        ))

    return findings

def check_access_key_age(session, max_age=90):
    """Checks whether the access key is older than 90 days"""
    iam = session.client("iam")
    findings = []

    paginator = iam.get_paginator("list_users") # Keep calling list_users() until there are no more
    for page in paginator.paginate(): # paginator.paginate() creates a list of pages
        for user in page['Users']:
            keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                age = datetime.now(timezone.utc) - key['CreateDate']
                if key['Status'] == "Active" and age.days > max_age:
                    findings.append(Finding(
                        check_id="CIS-1.13",
                        resource=key['UserName'],
                        severity=2,
                        description=(
                            f"{key['UserName']}'s access key ({key['AccessKeyId']}) "
                            f"is older than {max_age} days. The access key is {age.days} days old."
                        ),
                        remediation="Generate new access keys",
                        steps=(
                            f"(Search Bar > IAM > IAM users > {key['UserName']} > Security credentials "
                            "Access keys > Create Access Key > Update Applications with New Access Keys > "
                            "Actions > Deactivate old key > Actions > Delete old key)"
                        )
                    ))

    return findings

def check_open_ssh(session, port=22):
    """Flag security groups allowing ingress to specified port from the entire internet"""
    ec2 = session.client("ec2", region_name="ap-southeast-2")
    findings = []

    regions = ec2.describe_regions()['Regions']
    for region in regions:
        regional_client = session.client("ec2", region_name=region['RegionName'])
        paginator = regional_client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for group in page['SecurityGroups']:
                for rule in group['IpPermissions']: # If port is out of range then it is secure
                    if not (rule.get("FromPort", 0) <= port <= rule.get("ToPort", 65535)):
                        continue
                    for ip in rule.get("IpRanges", []):
                        if ip["CidrIp"] == "0.0.0.0/0":
                            findings.append(Finding(
                                check_id="CIS-5.3",
                                resource=f"{group['GroupName']} ({group['GroupId']}, {region['RegionName']})",
                                severity=4,
                                description=(
                                    "Security groups allow ingress from 0.0.0.0/0 to remote "
                                    "server administration ports"
                                ),
                                remediation="Restrict the source CIDR to known ranges or remove the rule",
                                steps=(
                                    f"(Search Bar > EC2 > Security Groups > {group['GroupId']} > "
                                    "Inbound rules > Edit inbound rules > Configure appropriate rules)"
                                )
                            ))
                    for ipv6 in rule.get("Ipv6Ranges", []):
                        if ipv6["CidrIpv6"] == "::/0":
                            findings.append(Finding(
                                check_id="CIS-5.4",
                                resource=f"{group['GroupName']} ({group['GroupId']}, {region['RegionName']})",
                                severity=4,
                                description=(
                                    "Security groups allow ingress from ::/0 to remote "
                                    "server administration ports"
                                ),
                                remediation="Restrict the source CIDR to known ranges or remove the rule",
                                steps=(
                                    f"(Search Bar > EC2 > Security Groups > {group['GroupId']} > "
                                    "Inbound rules > Edit inbound rules > Configure appropriate rules)"
                                )
                            ))

    return findings


if __name__ == "__main__":
    session = boto3.Session(profile_name="cspm") # Starts a session with local saved access keys
    findings = []
    findings += check_s3_public_access_block(session)
    findings += check_root_mfa(session)
    findings += check_access_key_age(session)
    findings += check_open_ssh(session)

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