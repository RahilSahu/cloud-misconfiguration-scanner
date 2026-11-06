# Cloud Misconfiguration Scanner

A zero-dependency Python scanner that checks public exposure and
dangerous configuration across **AWS, Microsoft Azure, Google Cloud
and Oracle Cloud (OCI)**, the four clouds where a single wrong setting
turns private files into public ones.

Most cloud breaches are not zero-days. They are a bucket made public,
a firewall rule opened to the world during debugging and never
closed, a policy with a wildcard in it. This tool looks for exactly
those mistakes, from two directions.

## 1. Public exposure checks (no credentials)

The tool asks each cloud the question any anonymous internet user
could ask: can I list this storage, read this file, see its
permissions?

| Cloud | Command | What it proves |
| --- | --- | --- |
| AWS S3 | `s3 BUCKET` | Anonymous listing, public ACL grants (AllUsers, AuthenticatedUsers), website hosting, a read test on the first object, and whether the bucket policy itself is publicly readable (it is then analysed too) |
| Azure Blob | `azure ACCOUNT CONTAINER` | Anonymous container listing, plus a read test on the first blob |
| GCP Storage | `gcs BUCKET` | Anonymous listing via XML and JSON APIs, whether the IAM policy is publicly readable, and public IAM bindings (allUsers, allAuthenticatedUsers) inside it |
| OCI Object Storage | `oci NAMESPACE BUCKET --region REGION` | Anonymous object listing on public buckets |

Findings are severity rated, and a listing that exposes files plus a
successful anonymous read of the first file is reported as critical
with the filename as evidence.

## 2. Configuration analysis (offline)

Export JSON with your normal cloud CLI and analyse it locally. No
credentials leave your machine, nothing is sent anywhere.

| Input | Export with | Checks |
| --- | --- | --- |
| AWS IAM / bucket policy | `aws iam get-policy-version`, `aws s3api get-bucket-policy` | Public principals without conditions, wildcard actions and resources |
| AWS security groups | `aws ec2 describe-security-groups` | 0.0.0.0/0 and ::/0 ingress on SSH, RDP, databases and more, all-ports-open rules |
| Azure NSG | `az network nsg show` | Internet and wildcard sources inbound on sensitive ports |
| GCP firewall | `gcloud compute firewall-rules list --format=json` | 0.0.0.0/0 sources on sensitive ports, all-ports rules |
| OCI security list | `oci network security-list get` | 0.0.0.0/0 ingress on sensitive ports |

## 3. Fleet mode

Scan many targets across all four clouds in one concurrent run, and
export a JSON report for your records or pipeline:

```bash
python3 cloud_scan.py --output report.json scan targets.json --workers 8
```

`targets.json` is a simple list:

```json
[
  {"type": "s3", "bucket": "my-bucket"},
  {"type": "azure", "account": "myaccount", "container": "uploads"},
  {"type": "gcs", "bucket": "my-bucket"},
  {"type": "oci", "namespace": "mynamespace", "bucket": "backups", "region": "ap-mumbai-1"}
]
```

## Usage examples

```bash
python3 cloud_scan.py s3 my-bucket
python3 cloud_scan.py azure myaccount uploads
python3 cloud_scan.py gcs my-bucket
python3 cloud_scan.py oci mynamespace backups --region ap-mumbai-1
python3 cloud_scan.py policy bucket-policy.json
python3 cloud_scan.py aws-sg security-groups.json
python3 cloud_scan.py azure-nsg nsg.json
python3 cloud_scan.py gcp-firewall firewall-rules.json
python3 cloud_scan.py oci-rules security-list.json
```

Exit code is 1 when a critical or high finding is present, so scans
drop cleanly into CI and cron jobs.

## Verified detection

Against Google's intentionally public `gcp-public-data-landsat`
bucket, the scanner reports the public listing as critical and counts
the exposed objects. Against private and non-existent targets across
AWS, Azure, GCP and OCI it reports clean, with a note explaining what
the cloud answered.

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

27 offline unit tests cover every classifier and analyser, including
mocked multi-target scans:

```bash
python3 -m unittest discover -s tests
```

## Roadmap

- Authenticated deep audits using each cloud's SDK (S3 Block Public
  Access, Azure storage account settings, GCP bucket IAM in full,
  OCI bucket visibility) behind optional extras
- Azure storage account and GCP project firewall exports in fleet mode

## Responsible use

Only scan cloud resources you own or are explicitly authorised to
test. The exposure checks send the same anonymous requests any
internet user could send, but intent and authorisation still matter.

## License

MIT, see LICENSE.
