import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloud_scan import (
    analyse_aws_sg,
    analyse_azure_nsg,
    analyse_gcp_firewall,
    analyse_oci_rules,
    analyse_policy,
    classify_azure,
    classify_gcs,
    classify_oci,
    classify_s3,
    parse_s3_public_grants,
)

S3_LIST = """<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Contents><Key>secret.txt</Key></Contents>
<Contents><Key>photo.jpg</Key></Contents>
</ListBucketResult>"""

S3_ACL_PUBLIC = """<?xml version="1.0"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<AccessControlList>
<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>
<Permission>WRITE</Permission></Grant>
</AccessControlList></AccessControlPolicy>"""

AZURE_LIST = """<?xml version="1.0"?>
<EnumerationResults><Blobs><Blob><Name>a.txt</Name></Blob><Blob><Name>b.txt</Name></Blob></Blobs></EnumerationResults>"""


class S3Tests(unittest.TestCase):
    def test_public_listing_and_read_are_critical(self):
        result = classify_s3("data", 200, S3_LIST, 403, "", 404, 200)
        severities = {f.severity for f in result.findings}
        self.assertIn("critical", severities)
        checks = {f.check for f in result.findings}
        self.assertIn("Public bucket listing", checks)
        self.assertIn("Public object read", checks)

    def test_private_bucket_has_no_findings(self):
        result = classify_s3("data", 403, "", 403, "", 404, None)
        self.assertEqual(result.findings, [])

    def test_missing_bucket_is_a_note(self):
        result = classify_s3("nope", 404, "NoSuchBucket", 404, "", 404, None)
        self.assertEqual(result.findings, [])
        self.assertTrue(any("does not exist" in n for n in result.notes))

    def test_public_acl_write_grant_is_critical(self):
        grants = parse_s3_public_grants(S3_ACL_PUBLIC)
        self.assertEqual(len(grants), 1)
        result = classify_s3("data", 403, "", 200, S3_ACL_PUBLIC, 404, None)
        self.assertEqual(result.findings[0].severity, "critical")


class AzureTests(unittest.TestCase):
    def test_public_container_is_critical(self):
        result = classify_azure("acct", "files", 200, AZURE_LIST)
        self.assertEqual(result.findings[0].severity, "critical")

    def test_denied_container_is_clean(self):
        result = classify_azure("acct", "files", 403, "")
        self.assertEqual(result.findings, [])


class GcsTests(unittest.TestCase):
    def test_public_listing_is_critical(self):
        result = classify_gcs("bucket", 200, S3_LIST, 200)
        self.assertTrue(any(f.severity == "critical" for f in result.findings))

    def test_denied_is_clean(self):
        result = classify_gcs("bucket", 403, "", 403)
        self.assertEqual(result.findings, [])


class OciTests(unittest.TestCase):
    def test_public_bucket_is_critical(self):
        body = json.dumps({"objects": [{"name": "a.txt"}, {"name": "b.txt"}]})
        result = classify_oci("ns", "bucket", "ap-mumbai-1", 200, body)
        self.assertEqual(result.findings[0].severity, "critical")

    def test_private_bucket_is_clean(self):
        result = classify_oci("ns", "bucket", "ap-mumbai-1", 404, "")
        self.assertEqual(result.findings, [])


class PolicyTests(unittest.TestCase):
    def test_public_bucket_policy_is_critical(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal": "*",
                              "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
        findings = analyse_policy(doc)
        self.assertTrue(any(f.severity == "critical" for f in findings))

    def test_public_policy_with_condition_is_not_flagged_as_public(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal": "*",
                              "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
                              "Condition": {"StringEquals": {"aws:SourceOrg": "o-123"}}}]}
        findings = analyse_policy(doc)
        self.assertFalse(any(f.check == "Public policy statement" for f in findings))

    def test_admin_policy_is_high(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        findings = analyse_policy(doc)
        self.assertTrue(any(f.severity == "high" for f in findings))

    def test_scoped_policy_is_clean(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                              "Resource": "arn:aws:s3:::b/public/*",
                              "Principal": {"AWS": "arn:aws:iam::123456789012:user/reader"}}]}
        self.assertEqual(analyse_policy(doc), [])


class FirewallTests(unittest.TestCase):
    def test_aws_sg_ssh_open_is_critical(self):
        doc = {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}
        findings = analyse_aws_sg(doc)
        self.assertTrue(any(f.severity == "critical" for f in findings))

    def test_aws_sg_internal_only_is_clean(self):
        doc = {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}
        self.assertEqual(analyse_aws_sg(doc), [])

    def test_aws_sg_all_open_is_critical(self):
        doc = {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}
        findings = analyse_aws_sg(doc)
        self.assertTrue(any("All ports" in f.check for f in findings))

    def test_azure_nsg_rdp_open(self):
        doc = {"securityRules": [{"name": "rdp", "properties": {
            "access": "Allow", "direction": "Inbound", "protocol": "Tcp",
            "sourceAddressPrefix": "Internet", "destinationPortRange": "3389"}}]}
        findings = analyse_azure_nsg(doc)
        self.assertTrue(any(f.severity == "critical" for f in findings))

    def test_gcp_firewall_mysql_open(self):
        doc = [{"name": "db", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["3306"]}]}]
        findings = analyse_gcp_firewall(doc)
        self.assertTrue(any(f.severity == "high" for f in findings))

    def test_gcp_firewall_disabled_rule_ignored(self):
        doc = [{"name": "db", "direction": "INGRESS", "disabled": True,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["3306"]}]}]
        self.assertEqual(analyse_gcp_firewall(doc), [])

    def test_oci_rule_ssh_open(self):
        doc = {"ingressSecurityRules": [{"source": "0.0.0.0/0", "protocol": "6",
                "tcpOptions": {"destinationPortRange": {"min": 22, "max": 22}}}]}
        findings = analyse_oci_rules(doc)
        self.assertTrue(any(f.severity == "critical" for f in findings))


if __name__ == "__main__":
    unittest.main()
