import boto3
from freezegun import freeze_time
from moto import mock_aws
from main import check_access_key_age

@mock_aws
def test_flag_old_active_key():
    """Creates a user with an active key from years ago"""
    with freeze_time("2020-01-01"):
        iam = boto3.client("iam", region_name="ap-southeast-2")
        iam.create_user(UserName="test-user")
        iam.create_access_key(UserName="test-user")

    session = boto3.Session(region_name="ap-southeast-2") # mock_aws doesn't take credentials
    findings = check_access_key_age(session)

    assert len(findings) == 1
    assert "test-user" in findings[0].resource
    assert findings[0].check_id == "CIS-1.13"