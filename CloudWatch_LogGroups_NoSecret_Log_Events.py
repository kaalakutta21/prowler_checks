#!/usr/bin/env python3

import boto3
import argparse
import csv
import re
from datetime import datetime, timedelta, timezone
from tqdm import tqdm
from botocore.exceptions import ClientError

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="cloudwatch-log-secrets-audit"
        )

        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )

    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")

    regions = ec2.describe_regions(AllRegions=True)["Regions"]

    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================

def classify_error(e):
    return e.response["Error"]["Code"]


def mask_value(value, keep_start=4, keep_end=4):
    if not value:
        return ""
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return value[:keep_start] + "*" * (len(value) - keep_start - keep_end) + value[-keep_end:]


def mask_snippet(text, secret_value):
    if not text or not secret_value:
        return text
    return text.replace(secret_value, mask_value(secret_value))


def clip_text(text, max_len=180):
    if text is None:
        return ""
    text = text.replace("\n", " ").replace("\r", " ")
    return text if len(text) <= max_len else text[:max_len] + "..."


def skipped_row(region, log_group_arn, reason):
    return {
        "Region": region,
        "LogGroupName": "N/A",
        "LogGroupArn": log_group_arn,
        "LogStreamName": "N/A",
        "EventTimestamp": "N/A",
        "DetectorType": "N/A",
        "MatchedPreview": "N/A",
        "SnippetPreview": "N/A",
        "Status": "SKIPPED",
        "Evidence": reason
    }


def log_group_arn(region, account_id, log_group_name):
    return f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}"


def build_detectors():
    return [
        {
            "name": "AWS Access Key ID",
            "pattern": re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
            "require_context": False
        },
        {
            "name": "JWT Token",
            "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
            "require_context": False
        },
        {
            "name": "Private Key",
            "pattern": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            "require_context": False
        },
        {
            "name": "Bearer Token",
            "pattern": re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]+=*)"),
            "require_context": False
        },
        {
            "name": "Password Assignment",
            "pattern": re.compile(
                r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]?([^\s'\";,]{8,})"
            ),
            "require_context": True
        },
        {
            "name": "API Key Assignment",
            "pattern": re.compile(
                r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]?([^\s'\";,]{12,})"
            ),
            "require_context": True
        },
        {
            "name": "AWS Secret Access Key Assignment",
            "pattern": re.compile(
                r"(?i)\b(aws[_-]?secret[_-]?access[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"
            ),
            "require_context": True
        },
        {
            "name": "Credential in URL",
            "pattern": re.compile(
                r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:([^/\s@]+)@[^/\s]+\b"
            ),
            "require_context": False
        },
    ]


def detect_secrets_in_message(message, detectors):
    findings = []

    for detector in detectors:
        for match in detector["pattern"].finditer(message):
            groups = match.groups()

            if detector["name"] in ["Password Assignment", "API Key Assignment", "AWS Secret Access Key Assignment"]:
                secret_value = groups[-1]
            elif detector["name"] == "Bearer Token":
                secret_value = groups[0]
            elif detector["name"] == "Credential in URL":
                secret_value = groups[0]
            else:
                secret_value = match.group(0)

            # conservative filters
            if not secret_value:
                continue

            if len(secret_value) < 8:
                continue

            if secret_value.lower() in {"password", "changeme", "example", "sample", "test12345"}:
                continue

            findings.append({
                "detector": detector["name"],
                "secret_value": secret_value,
                "match_text": match.group(0)
            })

    return findings


# ==================================================
# CONTROL LOGIC
# ==================================================
#
# Control:
# CloudWatch log groups contain no secret in log events
#
# Conservative implementation:
# - scans recent log events
# - uses regex + context-based detectors
# - avoids entropy-only detections to reduce false positives
# - marks log group NON_COMPLIANT if any secret-like event is found
# ==================================================

def check_control(session, lookback_days=7, max_streams_per_group=20, max_events_per_stream=200):
    account_id = get_account_id(session)
    regions = get_regions(session)
    detectors = build_detectors()

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)
    start_ms = int(start_time.timestamp() * 1000)

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            logs = session.client("logs", region_name=region)
        except ClientError as e:
            skipped += 1
            results.append(skipped_row(region, "N/A", f"Client init failed: {classify_error(e)}"))
            continue

        try:
            lg_paginator = logs.get_paginator("describe_log_groups")
        except ClientError as e:
            skipped += 1
            results.append(skipped_row(region, "N/A", f"describe_log_groups paginator failed: {classify_error(e)}"))
            continue

        try:
            for lg_page in lg_paginator.paginate():
                for lg in lg_page.get("logGroups", []):

                    log_group_name = lg["logGroupName"]
                    lg_arn = lg.get("arn", log_group_arn(region, account_id, log_group_name))

                    total_checked += 1
                    group_has_secret = False

                    try:
                        stream_resp = logs.describe_log_streams(
                            logGroupName=log_group_name,
                            orderBy="LastEventTime",
                            descending=True,
                            limit=max_streams_per_group
                        )
                        streams = stream_resp.get("logStreams", [])
                    except ClientError as e:
                        skipped += 1
                        results.append({
                            "Region": region,
                            "LogGroupName": log_group_name,
                            "LogGroupArn": lg_arn,
                            "LogStreamName": "N/A",
                            "EventTimestamp": "N/A",
                            "DetectorType": "N/A",
                            "MatchedPreview": "N/A",
                            "SnippetPreview": "N/A",
                            "Status": "SKIPPED",
                            "Evidence": f"describe_log_streams failed: {classify_error(e)}"
                        })
                        continue

                    for stream in streams:
                        stream_name = stream.get("logStreamName", "N/A")

                        try:
                            events_resp = logs.get_log_events(
                                logGroupName=log_group_name,
                                logStreamName=stream_name,
                                startTime=start_ms,
                                startFromHead=False,
                                limit=max_events_per_stream
                            )
                            events = events_resp.get("events", [])
                        except ClientError as e:
                            skipped += 1
                            results.append({
                                "Region": region,
                                "LogGroupName": log_group_name,
                                "LogGroupArn": lg_arn,
                                "LogStreamName": stream_name,
                                "EventTimestamp": "N/A",
                                "DetectorType": "N/A",
                                "MatchedPreview": "N/A",
                                "SnippetPreview": "N/A",
                                "Status": "SKIPPED",
                                "Evidence": f"get_log_events failed: {classify_error(e)}"
                            })
                            continue

                        for event in events:
                            message = event.get("message", "")
                            event_ts = event.get("timestamp", 0)

                            findings = detect_secrets_in_message(message, detectors)

                            for finding in findings:
                                group_has_secret = True

                                masked_match = mask_value(finding["secret_value"])
                                masked_snippet = clip_text(mask_snippet(message, finding["secret_value"]))

                                results.append({
                                    "Region": region,
                                    "LogGroupName": log_group_name,
                                    "LogGroupArn": lg_arn,
                                    "LogStreamName": stream_name,
                                    "EventTimestamp": str(event_ts),
                                    "DetectorType": finding["detector"],
                                    "MatchedPreview": masked_match,
                                    "SnippetPreview": masked_snippet,
                                    "Status": "NON_COMPLIANT",
                                    "Evidence": f"Detected likely secret in log event using detector: {finding['detector']}"
                                })

                    if group_has_secret:
                        non_compliant += 1
                    else:
                        compliant += 1
                        results.append({
                            "Region": region,
                            "LogGroupName": log_group_name,
                            "LogGroupArn": lg_arn,
                            "LogStreamName": "",
                            "EventTimestamp": "",
                            "DetectorType": "",
                            "MatchedPreview": "",
                            "SnippetPreview": "",
                            "Status": "COMPLIANT",
                            "Evidence": f"No likely secrets detected in scanned events from the last {lookback_days} day(s)"
                        })

        except ClientError as e:
            skipped += 1
            results.append(skipped_row(region, "N/A", f"Region scan failed: {classify_error(e)}"))
            continue

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):
    filename = f"cloudwatch_log_groups_no_secrets_{account_id}.csv"

    fields = [
        "Account",
        "Region",
        "LogGroupName",
        "LogGroupArn",
        "LogStreamName",
        "EventTimestamp",
        "DetectorType",
        "MatchedPreview",
        "SnippetPreview",
        "Status",
        "Evidence"
    ]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for row in results:
            writer.writerow({
                "Account": account_id,
                **row
            })

    return filename


# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="CloudWatch log groups contain no secret in log events"
    )

    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume for the audit")
    parser.add_argument("--lookback-days", type=int, default=7, help="Days of logs to scan (default: 7)")
    parser.add_argument("--max-streams-per-group", type=int, default=20, help="Max streams per log group (default: 20)")
    parser.add_argument("--max-events-per-stream", type=int, default=200, help="Max events per stream (default: 200)")

    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant, skipped = check_control(
        session,
        lookback_days=args.lookback_days,
        max_streams_per_group=args.max_streams_per_group,
        max_events_per_stream=args.max_events_per_stream
    )

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print("\n====================================================")
    print("CONTROL : CloudWatch Log Groups Contain No Secret In Log Events")
    print(f"ACCOUNT : {account_id}")
    print("====================================================")
    print(f"Total Checked  : {total_checked}")
    print(f"Compliant      : {compliant}")
    print(f"Non-Compliant  : {non_compliant}")
    print(f"Skipped        : {skipped}")
    print(f"\nOVERALL STATUS : {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Generated  : {csv_file}\n")


if __name__ == "__main__":
    main()
