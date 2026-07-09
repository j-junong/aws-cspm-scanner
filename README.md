# AWS CSPM Scanner

A Python-based Cloud Security Posture Management tool that 
scans an AWS account for misconfigurations against the CIS
AWS Foundations Benchmark v5.0.0 and produces prioritized 
remediation reports. Currently implements 6 controls across
IAM, S3, and EC2, verified by a 13-test suite.

## Sample Output
```commandline
3 findings:
[SEVERITY 4] CIS-5.3
  Resource    - cspm-test-open-ssh (sg-055eb15eb868e82e7, ap-southeast-2)
  Description - Security groups allow ingress from 0.0.0.0/0 to port 22
  Remediation - Restrict the source CIDR to known ranges or remove the rule
  Steps       - (Search Bar > EC2 > Security Groups > sg-055eb15eb868e82e7 > Inbound rules > Edit inbound rules > Configure appropriate rules for port 22)
[SEVERITY 3] CIS-2.1.4
  Resource    - jj-cspm-neverconf-1234
  Description - Bucket 'jj-cspm-neverconf-1234' does not block all public access.
  Remediation - Enable all four Block Public Access settings on bucket
  Steps       - (Search Bar > S3 > Bucket > jj-cspm-neverconf-1234 > Permissions > Block public access (bucket settings) > Edit > Tick Block all public access)
[SEVERITY 3] CIS-2.1.4
  Resource    - test-bucket-insecure-0
  Description - Bucket 'test-bucket-insecure-0' does not block all public access.
  Remediation - Enable all four Block Public Access settings on bucket
  Steps       - (Search Bar > S3 > Bucket > test-bucket-insecure-0 > Permissions > Block public access (bucket settings) > Edit > Tick Block all public access)
```
Findings can also be exported as JSON for machine use:
```json
"findings": [
    {
      "check_id": "CIS-5.3",
      "resource": "cspm-test-open-ssh (sg-055eb15eb868e82e7, ap-southeast-2)",
      "severity": 4,
      "description": "Security groups allow ingress from 0.0.0.0/0 to port 22",
      "remediation": "Restrict the source CIDR to known ranges or remove the rule",
      "steps": "(Search Bar > EC2 > Security Groups > sg-055eb15eb868e82e7 > Inbound rules > Edit inbound rules > Configure appropriate rules for port 22)"
    }
]
```
## Checks Implemented
| Control   | Detects                                                                                   | Severity |
|-----------|-------------------------------------------------------------------------------------------|----------|
| CIS-1.3   | Root account access keys enabled                                                          | 4        |
| CIS-1.4   | Root account has MFA disabled                                                             | 4        |
| CIS-1.13  | IAM users with active access keys older than 90 days                                      | 2        |
| CIS-2.1.4 | S3 buckets without full Block Public Access configuration                                 | 3        |
| CIS-5.3   | EC2 security groups allowing ingress from 0.0.0.0/0 to remote server administration ports | 4        |
| CIS-5.4   | EC2 security groups allowing ingress from ::/0 to remote server administration ports      | 4        |

## How It Works
Each CIS control is implemented as a Python function that accepts
a `boto3` session and returns a list of `Finding` objects. 

The `Finding` dataclass stores:
- CIS control ID
- Affected resource
- Severity
- Description
- Remediation advice
- Remediation steps

The scanner collects the findings from the implemented check,
sorts them by severity, and passes them to a reporting module
that formats either to console or a separate JSON file.

Authentication is performed using an AWS profile with the 
`SecurityAudit` managed policy attached, obeying the principle
of least privilege.

For EC2-related controls, the scanner automatically enumerates every
AWS region so resources are not missed even if they are outside the
default region.

## Running It
Requires Python 3.12+ and an AWS profile with the `SecurityAudit`
managed policy attached.

```commandline
git clone repo # TODO
cd cspm
python -m venv .venv
.venv\scripts\activate    # Windows
pip install -r requirements.txt

python main.py --profile your-profile-name
python main.py --json report.json
```

## Testing
The project includes automated tests using `pytest` together with `moto`, 
which provides a fully mocked AWS environment. This allows every security 
check to be tested without AWS credentials, network access, or cloud resources.

The test suite contains 13 unit tests covering both detection and non-detection 
paths for every implemented CIS control.

Additional tests verify that EC2 checks correctly enumerate every AWS region by 
placing intentionally vulnerable security groups into regions other than the 
default.

False-positive guards are also included to ensure the scanner ignores legitimate 
configurations such as public HTTPS access, inactive IAM access keys, and an IAM 
user named "root", which should not be mistaken for the AWS root account.

```commandline
python -m pytest -v
```

## Known Coverage Gaps
### MFA Support in `moto`
Date: 2026-07-06

Automated testing of the root MFA control's passing path was attempted.

The experiments showed that enable_mfa_device() only accepts IAM users. 
Setting `UserName="root"` raises a `NoSuchEntity` error.

Enabling MFA on a regular IAM user does not change `AccountMFAEnabled`.
Because of this limitation, the check is manually validated against a real AWS
account instead.

### Root Access Keys in `moto`
Date: 2026-07-08

Automated testing of the root access keys control's passing path was attempted.

Similar to MFA Support, create_access_key() only works for IAM users and not the
root account. Creating an access key with `UserName="root"` does not increment 
`AccountAccessKeyPresent`.

The root key detection logic is therefore validated using manual
testing in AWS.

## Roadmap
- Implement additional CIS AWS Foundations Benchmark controls
- Add async multiregion scanning to reduce execution time
- Generate HTML and CSV reports alongside the existing console and JSON outputs
