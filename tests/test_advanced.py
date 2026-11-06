import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cloud_scan
from cloud_scan import ScanResult, analyse_gcs_iam, classify_azure, scan_targets

AZURE_LIST = """<?xml version="1.0"?>
<EnumerationResults><Blobs><Blob><Name>report.pdf</Name></Blob></Blobs></EnumerationResults>"""


class AzureAdvancedTests(unittest.TestCase):
    def test_public_blob_read_is_flagged(self):
        result = classify_azure("acct", "files", 200, AZURE_LIST, first_blob_status=200)
        checks = {f.check for f in result.findings}
        self.assertIn("Public blob read", checks)


class GcsIamTests(unittest.TestCase):
    def test_all_users_binding_is_critical(self):
        doc = {"bindings": [{"role": "roles/storage.objectViewer",
                             "members": ["allUsers"]}]}
        findings = analyse_gcs_iam(doc, "bucket")
        self.assertEqual(findings[0].severity, "critical")

    def test_all_authenticated_users_is_high(self):
        doc = {"bindings": [{"role": "roles/storage.objectViewer",
                             "members": ["allAuthenticatedUsers"]}]}
        findings = analyse_gcs_iam(doc, "bucket")
        self.assertEqual(findings[0].severity, "high")

    def test_normal_bindings_are_clean(self):
        doc = {"bindings": [{"role": "roles/storage.objectViewer",
                             "members": ["user:alice@example.com"]}]}
        self.assertEqual(analyse_gcs_iam(doc, "bucket"), [])


class MultiTargetTests(unittest.TestCase):
    def test_scan_targets_merges_and_sorts(self):
        def fake_s3(bucket, timeout=15.0):
            result = ScanResult()
            result.findings.append(cloud_scan.Finding("AWS", f"s3://{bucket}", "critical", "x", "y"))
            return result

        def fake_gcs(bucket, timeout=15.0):
            result = ScanResult()
            result.notes.append(f"gs://{bucket}: fine")
            return result

        targets = [{"type": "s3", "bucket": "a"}, {"type": "gcs", "bucket": "b"}]
        with mock.patch.object(cloud_scan, "scan_s3", fake_s3), \
             mock.patch.object(cloud_scan, "scan_gcs", fake_gcs):
            combined = scan_targets(targets, workers=2)
        self.assertEqual(combined.worst, "critical")
        self.assertEqual(len(combined.findings), 1)
        self.assertEqual(len(combined.notes), 1)

    def test_result_as_dict_counts(self):
        result = ScanResult()
        result.findings.append(cloud_scan.Finding("AWS", "r", "critical", "c", "d"))
        result.findings.append(cloud_scan.Finding("AWS", "r", "critical", "c", "d"))
        result.findings.append(cloud_scan.Finding("GCP", "r", "low", "c", "d"))
        data = cloud_scan.result_as_dict(result)
        self.assertEqual(data["counts"], {"critical": 2, "low": 1})


if __name__ == "__main__":
    unittest.main()
