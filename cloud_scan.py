#!/usr/bin/env python3
"""Cloud Misconfiguration Scanner.

Checks public exposure and dangerous configuration across the four
major clouds: AWS, Microsoft Azure, Google Cloud (GCP) and Oracle
Cloud (OCI).

Two kinds of checks:

1. Public exposure checks (no credentials needed). Given a storage
   target you own or are authorised to test, the tool asks the cloud
   the same question an anonymous internet user could ask: can I list
   this bucket, read this file, see its permissions?
   - AWS S3 buckets: anonymous listing, public ACL grants, website
     hosting, and a read test on the first listed object
   - Azure Blob containers: anonymous container listing
   - Google Cloud Storage buckets: anonymous listing (XML and JSON)
   - OCI Object Storage buckets: anonymous object listing

2. Configuration file analysis (fully offline). Feed it the JSON your
   cloud CLI already exports and it flags the classic mistakes:
   - AWS IAM and S3 bucket policies: public principals, wildcards
   - AWS security groups: world-open ingress on sensitive ports
   - Azure NSGs: internet-open inbound rules on sensitive ports
   - GCP firewall rules: 0.0.0.0/0 sources on sensitive ports
   - OCI security lists: 0.0.0.0/0 ingress on sensitive ports

Zero dependencies: Python 3.9+ standard library only. Only scan cloud
resources you own or are explicitly authorised to test.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

USER_AGENT = "cloud-scan/1.0 (+https://github.com/RahilSahu/cloud-misconfiguration-scanner)"
MAX_BODY = 256 * 1024

SENSITIVE_PORTS = {
    22: ("SSH", "critical"),
    3389: ("RDP", "critical"),
    3306: ("MySQL", "high"),
    5432: ("PostgreSQL", "high"),
    6379: ("Redis", "high"),
    27017: ("MongoDB", "high"),
    9200: ("Elasticsearch", "high"),
    1433: ("MSSQL", "high"),
    5900: ("VNC", "high"),
    21: ("FTP", "medium"),
    23: ("Telnet", "high"),
    80: ("HTTP", "low"),
    443: ("HTTPS", "low"),
    8080: ("HTTP-alt", "low"),
}


@dataclass
class Finding:
    cloud: str
    resource: str
    severity: str  # critical, high, medium, low, info
    check: str
    detail: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def worst(self) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if not self.findings:
            return "none"
        return max((f.severity for f in self.findings), key=lambda s: order[s])


def http_get(url: str, timeout: float = 15.0) -> tuple[int | None, str]:
    """GET a URL, returning (status, body capped). Errors give (None, '')."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(MAX_BODY).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(MAX_BODY).decode("utf-8", errors="replace")
        except Exception:
            return exc.code, ""
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None, ""


# ---------------------------------------------------------------- S3

def parse_s3_keys(body: str) -> list[str]:
    return re.findall(r"<Key>([^<]+)</Key>", body)


def parse_s3_public_grants(body: str) -> list[str]:
    """Return public grant descriptions found in an S3 ACL document."""
    grants: list[str] = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return grants
    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    for grant in root.iter():
        if not grant.tag.endswith("Grant"):
            continue
        grantee_type, uri, permission = "", "", ""
        for child in grant:
            if child.tag.endswith("Grantee"):
                for item in child:
                    if item.tag.endswith("URI"):
                        uri = item.text or ""
            if child.tag.endswith("Permission"):
                permission = child.text or ""
        if "AllUsers" in uri:
            grants.append(f"AllUsers (anyone on the internet): {permission}")
        elif "AuthenticatedUsers" in uri:
            grants.append(f"AuthenticatedUsers (any AWS account): {permission}")
    return grants


def classify_s3(bucket: str, list_status: int | None, list_body: str,
                acl_status: int | None, acl_body: str,
                website_status: int | None,
                first_key_status: int | None) -> ScanResult:
    result = ScanResult()
    resource = f"s3://{bucket}"
    if list_status is None:
        result.notes.append(f"{resource}: could not be reached (network error or invalid name).")
        return result
    if list_status == 404 or "NoSuchBucket" in list_body:
        result.notes.append(f"{resource}: bucket does not exist.")
        return result

    keys = parse_s3_keys(list_body)
    if list_status == 200:
        result.findings.append(Finding(
            "AWS", resource, "critical", "Public bucket listing",
            f"Anyone on the internet can list this bucket. {len(keys)} object key(s) visible in the first page of results."))
        if keys and first_key_status == 200:
            result.findings.append(Finding(
                "AWS", resource, "critical", "Public object read",
                f"Object '{keys[0]}' can be downloaded by anyone without credentials. Treat every file in this bucket as public."))
    elif list_status == 403:
        result.notes.append(f"{resource}: listing is denied to anonymous users (good).")

    if acl_status == 200:
        for grant in parse_s3_public_grants(acl_body):
            severity = "critical" if any(p in grant for p in ("WRITE", "FULL_CONTROL")) else "high"
            result.findings.append(Finding(
                "AWS", resource, severity, "Public ACL grant",
                f"Bucket ACL grants {grant}."))
    if website_status == 200:
        result.findings.append(Finding(
            "AWS", resource, "medium", "Static website hosting enabled",
            "S3 static website hosting is enabled on this bucket. Confirm that is intended and that no non-public files share the bucket."))
    return result


def scan_s3(bucket: str, timeout: float = 15.0) -> ScanResult:
    base = f"https://{bucket}.s3.amazonaws.com"
    list_status, list_body = http_get(base + "/", timeout)
    acl_status, acl_body = http_get(base + "/?acl", timeout)
    website_status, _ = http_get(base + "/?website", timeout)
    first_key_status = None
    keys = parse_s3_keys(list_body) if list_status == 200 else []
    if keys:
        first_key_status, _ = http_get(base + "/" + keys[0], timeout)
    result = classify_s3(bucket, list_status, list_body, acl_status, acl_body,
                         website_status, first_key_status)
    # Advanced probe: is the bucket policy itself readable, and if so,
    # does it grant anything public? Normally both answers are 403.
    policy_status, policy_body = http_get(base + "/?policy", timeout)
    if policy_status == 200:
        result.findings.append(Finding(
            "AWS", f"s3://{bucket}", "medium", "Bucket policy is publicly readable",
            "Anyone can read this bucket's policy. Policies reveal account IDs, principals and internal structure."))
        try:
            policy_doc = json.loads(policy_body)
            result.findings.extend(analyse_policy(policy_doc, f"s3://{bucket} policy"))
        except ValueError:
            pass
    return result


# -------------------------------------------------------------- Azure

def parse_azure_blob_names(body: str) -> list[str]:
    return re.findall(r"<Blob><Name>([^<]+)</Name>", body)


def classify_azure(account: str, container: str, status: int | None, body: str,
                   first_blob_status: int | None = None) -> ScanResult:
    result = ScanResult()
    resource = f"azure://{account}/{container}"
    if status is None:
        result.notes.append(f"{resource}: could not be reached.")
    elif status == 200 and "<EnumerationResults" in body:
        blobs = body.count("<Blob>")
        result.findings.append(Finding(
            "Azure", resource, "critical", "Public blob container",
            f"Anyone on the internet can list this container ({blobs} blob(s) in the first page) and download its blobs. "
            "Public blob access is the Azure equivalent of a public S3 bucket."))
        names = parse_azure_blob_names(body)
        if names and first_blob_status == 200:
            result.findings.append(Finding(
                "Azure", resource, "critical", "Public blob read",
                f"Blob '{names[0]}' can be downloaded by anyone without credentials. Treat every file in this container as public."))
    elif status == 404:
        result.notes.append(f"{resource}: container not found (or the storage account does not exist).")
    elif status in (403, 404, 409):
        result.notes.append(f"{resource}: anonymous listing denied (status {status}, good).")
    else:
        result.notes.append(f"{resource}: unexpected status {status}.")
    return result


def scan_azure(account: str, container: str, timeout: float = 15.0) -> ScanResult:
    base = f"https://{account}.blob.core.windows.net/{container}"
    status, body = http_get(base + "?restype=container&comp=list", timeout)
    first_blob_status = None
    if status == 200:
        names = parse_azure_blob_names(body)
        if names:
            first_blob_status, _ = http_get(f"{base}/{names[0]}", timeout)
    return classify_azure(account, container, status, body, first_blob_status)


# ---------------------------------------------------------------- GCP

def classify_gcs(bucket: str, xml_status: int | None, xml_body: str,
                 json_status: int | None) -> ScanResult:
    result = ScanResult()
    resource = f"gs://{bucket}"
    keys = parse_s3_keys(xml_body)  # GCS XML listing uses the same <Key> shape
    if xml_status == 200 and "<ListBucketResult" in xml_body:
        result.findings.append(Finding(
            "GCP", resource, "critical", "Public bucket listing",
            f"Anyone on the internet can list this bucket ({len(keys)} object(s) in the first page). "
            "Check IAM for allUsers or allAuthenticatedUsers bindings."))
    elif json_status == 200:
        result.findings.append(Finding(
            "GCP", resource, "high", "Public bucket metadata",
            "The bucket's metadata and object list are readable via the JSON API without credentials."))
    elif xml_status == 404 or "NoSuchBucket" in xml_body:
        result.notes.append(f"{resource}: bucket does not exist.")
    elif xml_status in (403, 401):
        result.notes.append(f"{resource}: anonymous listing denied (good).")
    elif xml_status is None:
        result.notes.append(f"{resource}: could not be reached.")
    else:
        result.notes.append(f"{resource}: unexpected status {xml_status}.")
    return result


def analyse_gcs_iam(doc: dict, bucket: str) -> list[Finding]:
    """Flag public IAM bindings in a GCS bucket IAM policy document."""
    findings: list[Finding] = []
    for binding in _as_list(doc.get("bindings")):
        members = [str(m) for m in _as_list(binding.get("members"))]
        role = str(binding.get("role", "unknown role"))
        for member in members:
            if member == "allUsers":
                findings.append(Finding(
                    "GCP", f"gs://{bucket}", "critical", "Public IAM binding (allUsers)",
                    f"The bucket IAM policy grants {role} to allUsers: literally everyone on the internet."))
            elif member == "allAuthenticatedUsers":
                findings.append(Finding(
                    "GCP", f"gs://{bucket}", "high", "Broad IAM binding (allAuthenticatedUsers)",
                    f"The bucket IAM policy grants {role} to allAuthenticatedUsers: anyone with any Google account."))
    return findings


def scan_gcs(bucket: str, timeout: float = 15.0) -> ScanResult:
    xml_status, xml_body = http_get(f"https://storage.googleapis.com/{bucket}", timeout)
    json_status, _ = http_get(f"https://storage.googleapis.com/storage/v1/b/{bucket}/o", timeout)
    result = classify_gcs(bucket, xml_status, xml_body, json_status)
    iam_status, iam_body = http_get(f"https://storage.googleapis.com/storage/v1/b/{bucket}/iam", timeout)
    if iam_status == 200:
        result.findings.append(Finding(
            "GCP", f"gs://{bucket}", "medium", "Bucket IAM policy is publicly readable",
            "Anyone can read this bucket's IAM policy, revealing who has access and how the project is structured."))
        try:
            result.findings.extend(analyse_gcs_iam(json.loads(iam_body), bucket))
        except ValueError:
            pass
    return result


# ---------------------------------------------------------------- OCI

def classify_oci(namespace: str, bucket: str, region: str,
                 status: int | None, body: str) -> ScanResult:
    result = ScanResult()
    resource = f"oci://{namespace}/{bucket} ({region})"
    if status == 200:
        try:
            objects = json.loads(body).get("objects", [])
            count = len(objects)
        except (ValueError, AttributeError):
            count = 0
        result.findings.append(Finding(
            "OCI", resource, "critical", "Public object storage bucket",
            f"Anyone on the internet can list this bucket ({count} object(s) in the response) and download its objects. "
            "The bucket visibility is Public, or a pre-authenticated request is exposed."))
    elif status == 404:
        result.notes.append(f"{resource}: bucket or namespace not found.")
    elif status in (401, 403, 409):
        result.notes.append(f"{resource}: anonymous listing denied (status {status}, good). A private bucket returns 404 or 401 here. ")
    elif status is None:
        result.notes.append(f"{resource}: could not be reached (check the region and namespace).")
    else:
        result.notes.append(f"{resource}: unexpected status {status}.")
    return result


def scan_oci(namespace: str, bucket: str, region: str, timeout: float = 15.0) -> ScanResult:
    url = f"https://objectstorage.{region}.oraclecloud.com/n/{namespace}/b/{bucket}/o"
    status, body = http_get(url, timeout)
    return classify_oci(namespace, bucket, region, status, body)


# ------------------------------------------------- policy analysis

def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_public_principal(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if "*" in _as_list(value):
                return True
    return False


def analyse_policy(doc: dict, source: str = "policy.json") -> list[Finding]:
    """Analyse an AWS IAM policy or S3 bucket policy document."""
    findings: list[Finding] = []
    for index, statement in enumerate(_as_list(doc.get("Statement"))):
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect", "Allow")).lower() != "allow":
            continue
        actions = [str(a) for a in _as_list(statement.get("Action"))]
        resources = [str(r) for r in _as_list(statement.get("Resource"))]
        public = _is_public_principal(statement.get("Principal"))
        has_condition = "Condition" in statement
        label = f"statement {index + 1}"

        if public and not has_condition:
            findings.append(Finding(
                "AWS", source, "critical", "Public policy statement",
                f"Policy {label} grants access to everyone (Principal *) with no Condition. "
                f"Actions: {', '.join(actions[:5]) or 'unspecified'}."))
        if any(a in ("*", "*:*") or a.endswith(":*") for a in actions) and "*" in resources:
            findings.append(Finding(
                "AWS", source, "high", "Wildcard action and resource",
                f"Policy {label} allows wildcard actions on every resource. This is effectively administrator access."))
        elif any(a == "*" for a in actions):
            findings.append(Finding(
                "AWS", source, "medium", "Wildcard action",
                f"Policy {label} allows every action on its resources. Scope it to the actions actually needed."))
    return findings


def _port_range_covers(port_from: int, port_to: int, port: int) -> bool:
    return port_from <= port <= port_to


def _check_open_ports(findings: list[Finding], cloud: str, resource: str,
                      source_open: bool, port_from: int, port_to: int, context: str) -> None:
    if not source_open:
        return
    hits = [(p, name, sev) for p, (name, sev) in SENSITIVE_PORTS.items()
            if _port_range_covers(port_from, port_to, p)]
    if port_from == 0 and port_to >= 65535:
        findings.append(Finding(cloud, resource, "critical", "All ports open to the internet",
                                f"{context}: every port is reachable from anywhere. This is the single most exploited cloud misconfiguration."))
        return
    for port, name, severity in hits:
        if severity in ("critical", "high"):
            findings.append(Finding(cloud, resource, severity, f"{name} open to the internet",
                                    f"{context}: port {port} ({name}) is reachable from 0.0.0.0/0 or the internet. Restrict the source or move the service behind a VPN or bastion."))
        elif severity == "medium":
            findings.append(Finding(cloud, resource, "medium", f"{name} open to the internet",
                                    f"{context}: port {port} ({name}) is reachable from anywhere. Confirm this exposure is intended."))


def analyse_aws_sg(doc: dict, source: str = "security-groups.json") -> list[Finding]:
    findings: list[Finding] = []
    for group in _as_list(doc.get("SecurityGroups")):
        gid = group.get("GroupId", "unknown")
        for perm in _as_list(group.get("IpPermissions")):
            open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in _as_list(perm.get("IpRanges")))
            open_v6 = any(r.get("CidrIpv6") == "::/0" for r in _as_list(perm.get("Ipv6Ranges")))
            if not (open_v4 or open_v6):
                continue
            protocol = str(perm.get("IpProtocol", "tcp"))
            if protocol == "-1":
                port_from, port_to = 0, 65535
            else:
                port_from = int(perm.get("FromPort", 0))
                port_to = int(perm.get("ToPort", 65535))
            _check_open_ports(findings, "AWS", f"{source}:{gid}", True, port_from, port_to,
                              f"Security group {gid}")
    return findings


def analyse_azure_nsg(doc: dict, source: str = "nsg.json") -> list[Finding]:
    findings: list[Finding] = []
    rules = []
    if isinstance(doc.get("securityRules"), list):
        rules = doc["securityRules"]
    elif isinstance(doc.get("properties", {}).get("securityRules"), list):
        rules = doc["properties"]["securityRules"]
    for rule in rules:
        props = rule.get("properties", rule)
        if str(props.get("access", "")).lower() != "allow":
            continue
        if str(props.get("direction", "")).lower() != "inbound":
            continue
        source_prefix = str(props.get("sourceAddressPrefix", ""))
        if source_prefix not in ("*", "Internet", "0.0.0.0/0"):
            continue
        port_spec = str(props.get("destinationPortRange", "*"))
        name = rule.get("name", "rule")
        if port_spec == "*":
            port_from, port_to = 0, 65535
        elif "-" in port_spec:
            a, b = port_spec.split("-", 1)
            port_from, port_to = int(a), int(b)
        else:
            port_from = port_to = int(port_spec)
        _check_open_ports(findings, "Azure", f"{source}:{name}", True, port_from, port_to,
                          f"NSG rule {name}")
    return findings


def analyse_gcp_firewall(doc, source: str = "firewall.json") -> list[Finding]:
    findings: list[Finding] = []
    rules = doc if isinstance(doc, list) else _as_list(doc.get("items"))
    for rule in rules:
        if rule.get("disabled"):
            continue
        if str(rule.get("direction", "INGRESS")).upper() != "INGRESS":
            continue
        if "0.0.0.0/0" not in _as_list(rule.get("sourceRanges")):
            continue
        name = rule.get("name", "rule")
        for allowed in _as_list(rule.get("allowed")):
            ports = _as_list(allowed.get("ports"))
            if not ports:  # protocol with no port list means all ports for it
                _check_open_ports(findings, "GCP", f"{source}:{name}", True, 0, 65535,
                                  f"Firewall rule {name}")
                continue
            for spec in ports:
                spec = str(spec)
                if "-" in spec:
                    a, b = spec.split("-", 1)
                    port_from, port_to = int(a), int(b)
                else:
                    port_from = port_to = int(spec)
                _check_open_ports(findings, "GCP", f"{source}:{name}", True, port_from, port_to,
                                  f"Firewall rule {name}")
    return findings


def analyse_oci_rules(doc: dict, source: str = "oci-security-list.json") -> list[Finding]:
    findings: list[Finding] = []
    for index, rule in enumerate(_as_list(doc.get("ingressSecurityRules"))):
        if str(rule.get("source", "")) != "0.0.0.0/0":
            continue
        if rule.get("isStateless"):
            continue
        tcp = rule.get("tcpOptions") or {}
        udp = rule.get("udpOptions") or {}
        options = tcp or udp
        label = f"ingress rule {index + 1}"
        if not options:  # no port options means all ports for that protocol
            _check_open_ports(findings, "OCI", source, True, 0, 65535, f"OCI security list {label}")
            continue
        dest = options.get("destinationPortRange") or {}
        port_from = int(dest.get("min", 0))
        port_to = int(dest.get("max", port_from))
        _check_open_ports(findings, "OCI", source, True, port_from, port_to,
                          f"OCI security list {label}")
    return findings


# ------------------------------------------------- multi-target scan

def scan_target(target: dict, timeout: float = 15.0) -> ScanResult:
    kind = str(target.get("type", "")).lower()
    if kind == "s3":
        return scan_s3(str(target["bucket"]), timeout)
    if kind == "azure":
        return scan_azure(str(target["account"]), str(target["container"]), timeout)
    if kind == "gcs":
        return scan_gcs(str(target["bucket"]), timeout)
    if kind == "oci":
        return scan_oci(str(target["namespace"]), str(target["bucket"]),
                        str(target.get("region", "ap-mumbai-1")), timeout)
    result = ScanResult()
    result.notes.append(f"Unknown target type skipped: {target}")
    return result


def scan_targets(targets: list[dict], workers: int = 8, timeout: float = 15.0) -> ScanResult:
    """Scan many targets concurrently and merge the results."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    combined = ScanResult()
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as pool:
        futures = [pool.submit(scan_target, target, timeout) for target in targets]
        for future in as_completed(futures):
            part = future.result()
            combined.findings.extend(part.findings)
            combined.notes.extend(part.notes)
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    combined.findings.sort(key=lambda f: -rank[f.severity])
    return combined


def result_as_dict(result: ScanResult) -> dict:
    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {"worst_severity": result.worst, "counts": counts,
            "notes": result.notes, "findings": [vars(f) for f in result.findings]}


# ---------------------------------------------------------------- CLI

def print_result(result: ScanResult) -> None:
    for note in result.notes:
        print(f"  {note}")
    for finding in sorted(result.findings, key=lambda f: -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f.severity]):
        print(f"[{finding.severity.upper()}] {finding.cloud} {finding.resource}")
        print(f"  {finding.check}: {finding.detail}")
    if not result.findings:
        print("  No misconfigurations found in what was checked.")
    else:
        counts: dict[str, int] = {}
        for finding in result.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        summary = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if s in counts)
        print(f"\nSummary: {summary}. Worst severity: {result.worst}.")


def load_json_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Cloud misconfiguration scanner for AWS, Azure, GCP and OCI.")
    parser.add_argument("--json", action="store_true", help="Print findings as JSON")
    parser.add_argument("--output", help="Also write the full JSON report to this file")
    parser.add_argument("--timeout", type=float, default=15.0)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="Scan many targets from a JSON targets file, concurrently")
    p.add_argument("file", help='JSON list, e.g. [{"type":"s3","bucket":"name"},{"type":"azure","account":"a","container":"c"},{"type":"gcs","bucket":"b"},{"type":"oci","namespace":"ns","bucket":"b","region":"ap-mumbai-1"}]')
    p.add_argument("--workers", type=int, default=8)

    p = sub.add_parser("s3", help="Check an AWS S3 bucket for public access")
    p.add_argument("bucket")

    p = sub.add_parser("azure", help="Check an Azure Blob container for public access")
    p.add_argument("account")
    p.add_argument("container")

    p = sub.add_parser("gcs", help="Check a Google Cloud Storage bucket for public access")
    p.add_argument("bucket")

    p = sub.add_parser("oci", help="Check an OCI Object Storage bucket for public access")
    p.add_argument("namespace")
    p.add_argument("bucket")
    p.add_argument("--region", default="ap-mumbai-1", help="OCI region, default ap-mumbai-1")

    p = sub.add_parser("policy", help="Analyse an AWS IAM or S3 bucket policy JSON file")
    p.add_argument("file")

    p = sub.add_parser("aws-sg", help="Analyse an AWS describe-security-groups JSON file")
    p.add_argument("file")

    p = sub.add_parser("azure-nsg", help="Analyse an Azure NSG JSON export")
    p.add_argument("file")

    p = sub.add_parser("gcp-firewall", help="Analyse a GCP firewall rules JSON export")
    p.add_argument("file")

    p = sub.add_parser("oci-rules", help="Analyse an OCI security list JSON export")
    p.add_argument("file")

    args = parser.parse_args(argv)
    result = ScanResult()
    try:
        if args.command == "scan":
            with open(args.file, encoding="utf-8") as fh:
                targets = json.load(fh)
            result = scan_targets(targets, workers=args.workers, timeout=args.timeout)
        elif args.command == "s3":
            result = scan_s3(args.bucket, args.timeout)
        elif args.command == "azure":
            result = scan_azure(args.account, args.container, args.timeout)
        elif args.command == "gcs":
            result = scan_gcs(args.bucket, args.timeout)
        elif args.command == "oci":
            result = scan_oci(args.namespace, args.bucket, args.region, args.timeout)
        elif args.command == "policy":
            result.findings = analyse_policy(load_json_file(args.file), args.file)
        elif args.command == "aws-sg":
            result.findings = analyse_aws_sg(load_json_file(args.file), args.file)
        elif args.command == "azure-nsg":
            result.findings = analyse_azure_nsg(load_json_file(args.file), args.file)
        elif args.command == "gcp-firewall":
            result.findings = analyse_gcp_firewall(load_json_file(args.file), args.file)
        elif args.command == "oci-rules":
            result.findings = analyse_oci_rules(load_json_file(args.file), args.file)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(result_as_dict(result), fh, indent=2)
    if args.json:
        print(json.dumps(result_as_dict(result), indent=2))
    else:
        print_result(result)
    return 1 if result.worst in ("critical", "high") else 0


if __name__ == "__main__":
    raise SystemExit(main())
