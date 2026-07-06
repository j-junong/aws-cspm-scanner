import boto3
from freezegun import freeze_time
from moto import mock_aws
from main import check_access_key_age, check_root_mfa

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


