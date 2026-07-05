import boto3

'''Creates a session'''
session = boto3.Session(profile_name='cspm')
s3 = session.client("s3")

'''Lists the existing buckets'''
response = s3.list_buckets()
for bucket in response["Buckets"]:
    print(bucket["Name"])

'''Checks which bucket can be accessed by the public'''
try:
    response = s3.get_public_access_block(Bucket="jj-cspm-neverconf-1234")
    config = response["PublicAccessBlockConfiguration"]
    fully_blocked = all(config.values())
except s3.exceptions.ClientError as e:
    if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
        fully_blocked = False
    else:
        raise

print(fully_blocked)