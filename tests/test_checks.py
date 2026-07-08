import boto3
from freezegun import freeze_time
from moto import mock_aws

from main import check_s3_public_access_block, check_access_key_age, check_root_mfa, check_open_admin_port, check_root_user_access_keys

@mock_aws
def test_flag_old_active_key():
    """Test 1: Creates a user and access key from years ago and flags it"""
    with freeze_time("2020-01-01"):
        iam = boto3.client("iam", region_name="ap-southeast-2")
        iam.create_user(UserName="old-user")
        iam.create_access_key(UserName="old-user")

    session = boto3.Session(region_name="ap-southeast-2") # moto doesn't take credentials
    findings = check_access_key_age(session)

    assert len(findings) == 1
    assert "old-user" in findings[0].resource
    assert findings[0].check_id == "CIS-1.13"

@mock_aws
def test_unflagged_fresh_key():
    """Test 2: Creates a fresh user and access key and does not flag it"""
    iam = boto3.client("iam", region_name="ap-southeast-2")
    iam.create_user(UserName="fresh-user")
    iam.create_access_key(UserName="fresh-user")

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_access_key_age(session)

    assert len(findings) == 0

@mock_aws
def test_unflagged_old_inactive_key():
    """Test 3: Creates a user and inactive access key and does not flag it"""
    with freeze_time("2020-01-01"):
        iam = boto3.client("iam", region_name="ap-southeast-2")
        iam.create_user(UserName="old-user")
        response = iam.create_access_key(UserName="old-user")
        key_id = response["AccessKey"]["AccessKeyId"]
        iam.update_access_key(UserName="old-user", AccessKeyId=key_id, Status="Inactive")

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_access_key_age(session)

    assert len(findings) == 0

@mock_aws
def test_flag_root_without_mfa():
    """Test 4: Flags root account if MFA is not enabled"""
    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_root_mfa(session)

    assert len(findings) == 1
    assert findings[0].severity == 4
    assert findings[0].check_id == "CIS-1.4"

# Note: the passing test of check_root_mfa (AccountMFAEnabled=1) cannot be
# simulated in moto: enable_mfa_device only works for IAM users (NoSuchEntity),
# and enabling MFA on a regular user does not change AccountMFAEnabled for the root account.
# Value shown for AccountMFAEnabled is strictly for the root account only.
# Verified and tested on 2026-07-06.

@mock_aws
def test_flag_open_ssh_ipv4():
    """Test 5: Flags security group open to 0.0.0.0/0 on port 22"""
    ec2 = boto3.client("ec2", region_name="ap-southeast-2")
    sg = ec2.create_security_group(
        GroupName="bad-ssh",
        Description="Bad ssh security group",
    )
    group_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_open_admin_port(session)

    assert len(findings) == 1
    assert group_id in findings[0].resource
    assert findings[0].severity == 4
    assert findings[0].check_id == "CIS-5.3"

@mock_aws
def test_flag_open_ssh_ipv6():
    """Test 6: Flags security group open to ::/0 on port 22"""
    ec2 = boto3.client("ec2", region_name="ap-southeast-2")
    sg = ec2.create_security_group(
        GroupName="bad-ssh-ipv6",
        Description="Bad ssh ipv6 security group",
    )
    group_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_open_admin_port(session)

    assert len(findings) == 1
    assert group_id in findings[0].resource
    assert findings[0].severity == 4
    assert findings[0].check_id == "CIS-5.4"

@mock_aws
def test_flag_open_ssh_other_region():
    """Test 7: Flags security group open to 0.0.0.0/0 on port 22 in another region"""
    ec2 = boto3.client("ec2", region_name="us-east-2")
    sg = ec2.create_security_group(
        GroupName="bad-ssh",
        Description="Bad ssh security group in another region",
    )
    group_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_open_admin_port(session)

    assert len(findings) == 1
    assert group_id in findings[0].resource
    assert findings[0].severity == 4
    assert findings[0].check_id == "CIS-5.3"
    assert "us-east-2" in findings[0].resource

@mock_aws
def test_unflagged_https_open_to_world():
    """Test 8: Does not flag security group open to 0.0.0.0/0 on port 443 (HTTPS)"""
    ec2 = boto3.client("ec2", region_name="ap-southeast-2")
    sg = ec2.create_security_group(
        GroupName="public-https",
        Description="HTTPS only security group",
    )
    group_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_open_admin_port(session)

    assert len(findings) == 0

@mock_aws
def test_unflagged_ticked_public_access_block():
    """Test 9: Does not flag buckets with enabled public access block permissions"""
    s3 = boto3.client("s3", region_name="ap-southeast-2")
    s3.create_bucket(
        Bucket="test-bucket",
        CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
    )
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    )

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_s3_public_access_block(session)

    assert len(findings) == 0

@mock_aws
def test_flag_unticked_public_access_block():
    """Test 10: Flag buckets with disabled public access block permissions"""
    s3 = boto3.client("s3", region_name="ap-southeast-2")
    s3.create_bucket(
        Bucket="test-bucket",
        CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
    )
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
        }
    )

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_s3_public_access_block(session)

    assert len(findings) == 1
    assert "CIS-2.1.4" in findings[0].check_id
    assert findings[0].severity == 3
    assert "test-bucket" in findings[0].resource

@mock_aws
def test_flag_missing_public_access_block():
    """Test 11: Flag buckets with missing public access block permissions"""
    s3 = boto3.client("s3", region_name="ap-southeast-2")
    s3.create_bucket(
        Bucket="test-bucket",
        CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
    )
    s3.delete_public_access_block(Bucket="test-bucket")

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_s3_public_access_block(session)

    assert len(findings) == 1
    assert findings[0].check_id == "CIS-2.1.4"
    assert findings[0].severity == 3
    assert "test-bucket" in findings[0].resource

@mock_aws
def test_flag_open_rdp():
    """Test 12: Flags security group open to 0.0.0.0/0 on port 3389 (RDP)"""
    ec2 = boto3.client("ec2", region_name="ap-southeast-2")
    sg = ec2.create_security_group(
        GroupName="bad-rdp",
        Description="Bad rdp security group",
    )
    group_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_open_admin_port(session, port=3389)

    assert len(findings) == 1
    assert group_id in findings[0].resource
    assert findings[0].severity == 4
    assert findings[0].check_id == "CIS-5.3"

@mock_aws
def test_unflagged_existing_iam_access_keys():
    iam = boto3.client("iam", region_name="ap-southeast-2")
    iam.create_user(UserName="root")
    iam.create_access_key(UserName="root")

    session = boto3.Session(region_name="ap-southeast-2")
    findings = check_root_user_access_keys(session)

    assert findings == []

# Unable to flag if root account access keys exist in moto as create_access_key() only works
# for IAM users only. AccountAccessKeysPresent cannot be raised via API (root keys have no
# API creation route). Verified against real AWS with a temp root key.