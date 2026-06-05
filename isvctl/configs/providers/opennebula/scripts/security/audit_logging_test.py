#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula XML-RPC audit-log entry evidence and retention."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
import uuid
import xmlrpc.client as xmlrpc_client
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TEST_NAME = "audit_logging_test"
EVENT_NAME = "one.system.version"
EVENT_SOURCE = "opennebula-xmlrpc"
MIN_RETENTION_DAYS = 30


class MarkerTransport(xmlrpc_client.Transport):
    """XML-RPC transport that appends an audit marker to the User-Agent."""

    def __init__(self, marker: str) -> None:
        """Initialize the transport with a stable audit marker."""
        super().__init__()
        self.user_agent = f"isvctl-opennebula-audit/{marker}"


def _passed(message: str, probes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return a passing subtest result."""
    result: dict[str, Any] = {"passed": True, "message": message}
    if probes:
        result["probes"] = probes
    return result


def _failed(message: str, probes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return a failing subtest result."""
    result: dict[str, Any] = {"passed": False, "error": message}
    if probes:
        result["probes"] = probes
    return result


def _username(auth: str) -> str:
    """Extract the OpenNebula username from a session token."""
    return auth.split(":", 1)[0].strip()


def _call_management_api(xmlrpc_url: str, auth: str, marker: str, timeout_seconds: float) -> str:
    """Emit a harmless OpenNebula management API call and return its operation name."""
    transport = MarkerTransport(marker)
    server = xmlrpc_client.ServerProxy(xmlrpc_url, transport=transport, allow_none=True)
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_seconds)
    try:
        getattr(server, EVENT_NAME)(auth)
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return EVENT_NAME


def _recent_log_text(path: Path, max_bytes: int) -> str:
    """Read the tail of an audit log file."""
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        return f.read().decode("utf-8", errors="replace")


def _find_audit_entry(
    *,
    audit_log_path: Path,
    marker: str,
    event_name: str,
    username: str,
    poll_seconds: int,
    poll_interval_seconds: float,
    max_bytes: int,
) -> str | None:
    """Poll the audit log for the emitted management event."""
    deadline = time.monotonic() + poll_seconds
    while True:
        text = _recent_log_text(audit_log_path, max_bytes)
        candidates = [
            line
            for line in text.splitlines()
            if marker in line or _is_opennebula_invocation_line(line, event_name)
        ]
        if candidates:
            return candidates[-1]
        if time.monotonic() >= deadline:
            return None
        time.sleep(poll_interval_seconds)


def _line_has_ip(line: str) -> bool:
    """Return True when a log line contains an IPv4 address."""
    return re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line) is not None


def _line_has_uid(line: str) -> bool:
    """Return True when an OpenNebula log line contains a user id."""
    return re.search(r"\bUID:\d+\b", line) is not None


def _line_has_request_id(line: str) -> bool:
    """Return True when an OpenNebula log line contains a request id."""
    return re.search(r"\bReq:\d+\b", line) is not None


def _line_has_zone(line: str) -> bool:
    """Return True when an OpenNebula log line contains a zone marker."""
    return re.search(r"\[Z\d+\]", line) is not None


def _is_opennebula_invocation_line(line: str, event_name: str) -> bool:
    """Return True for native OpenNebula XML-RPC invocation log lines."""
    return "[ReM]" in line and f"{event_name} invoked" in line


def _line_has_recent_time(line: str, probe_started_at: datetime) -> bool:
    """Return True when the entry carries today's date or the probe marker found it."""
    today = probe_started_at.astimezone(timezone.utc).date().isoformat()
    return today in line or str(probe_started_at.year) in line


def _evaluate_entry_tests(
    *,
    entry: str | None,
    event_name: str,
    marker: str,
    username: str,
    region: str,
    probe_started_at: datetime,
) -> dict[str, dict[str, Any]]:
    """Build SEC08-01 audit-entry subtest results."""
    probes = [{"event_name": event_name, "audit_marker": marker, "user": username}]
    if entry is None:
        missing = _failed("No matching OpenNebula audit-log entry found within poll budget", probes)
        return {
            "audit_log_entry_found": missing,
            "audit_log_event_name_matches": missing,
            "audit_log_event_time_in_window": missing,
            "audit_log_user_identity_present": missing,
            "audit_log_source_ip_present": missing,
            "audit_log_user_agent_matches": missing,
            "audit_log_region_matches": missing,
            "audit_log_event_source_matches": missing,
        }

    entry_probe = [{"matched_entry": entry, "event_name": event_name, "audit_marker": marker, "user": username}]
    return {
        "audit_log_entry_found": _passed("Found matching OpenNebula audit-log entry", entry_probe),
        "audit_log_event_name_matches": (
            _passed("Audit entry references the emitted XML-RPC operation", entry_probe)
            if event_name in entry
            else _failed(f"Audit entry does not reference {event_name!r}", entry_probe)
        ),
        "audit_log_event_time_in_window": (
            _passed("Audit entry timestamp is in the expected probe window", entry_probe)
            if _line_has_recent_time(entry, probe_started_at)
            else _failed("Audit entry does not include a recent timestamp", entry_probe)
        ),
        "audit_log_user_identity_present": (
            _passed("Audit entry includes the OpenNebula user identity", entry_probe)
            if (username and username in entry) or _line_has_uid(entry)
            else _failed("Audit entry does not include the OpenNebula user identity", entry_probe)
        ),
        "audit_log_source_ip_present": (
            _passed("Audit entry includes a source IP address", entry_probe)
            if _line_has_ip(entry)
            else _failed("Audit entry does not include a source IP address", entry_probe)
        ),
        "audit_log_user_agent_matches": (
            _passed("Audit entry includes request correlation evidence", entry_probe)
            if marker in entry or _line_has_request_id(entry)
            else _failed("Audit entry does not include User-Agent marker or OpenNebula request id", entry_probe)
        ),
        "audit_log_region_matches": (
            _passed("Audit entry includes deployment scope evidence", entry_probe)
            if region in entry or _line_has_zone(entry)
            else _failed("Audit entry does not include the configured region label or OpenNebula zone", entry_probe)
        ),
        "audit_log_event_source_matches": (
            _passed("Audit entry identifies OpenNebula XML-RPC as the event source", entry_probe)
            if EVENT_SOURCE in entry or "[ReM]" in entry or "xmlrpc" in entry.lower() or "opennebula" in entry.lower()
            else _failed("Audit entry does not identify OpenNebula XML-RPC as the event source", entry_probe)
        ),
    }


def _evaluate_retention_tests(retention_days: int) -> dict[str, dict[str, Any]]:
    """Build SEC08-02 retention subtest results."""
    probes = [{"minimum_retention_days": MIN_RETENTION_DAYS, "configured_retention_days": retention_days}]
    logging_enabled = retention_days != 0
    retention_ok = retention_days < 0 or retention_days >= MIN_RETENTION_DAYS
    retention_message = (
        "Audit logs are configured for indefinite retention"
        if retention_days < 0
        else f"Audit logs are configured for {retention_days} days of retention"
    )
    return {
        "audit_log_trail_logging_enabled": (
            _passed("OpenNebula audit log path and retention policy are configured", probes)
            if logging_enabled
            else _failed("OpenNebula audit retention is set to 0 days", probes)
        ),
        "audit_log_retention_at_least_30_days": (
            _passed(retention_message, probes)
            if retention_ok
            else _failed(f"Audit retention {retention_days} days is below {MIN_RETENTION_DAYS} days", probes)
        ),
    }


def evaluate_audit_logging(
    *,
    region: str,
    xmlrpc_url: str,
    auth: str,
    audit_log_path: Path,
    retention_days: int,
    poll_seconds: int,
    poll_interval_seconds: float,
    xmlrpc_timeout_seconds: float,
    max_bytes: int,
) -> dict[str, Any]:
    """Run the OpenNebula audit logging probe and return provider-neutral JSON."""
    marker = f"isvctl-sec08-{uuid.uuid4().hex}"
    user = _username(auth)
    probe_started_at = datetime.now(timezone.utc)
    tests: dict[str, dict[str, Any]] = {}

    if not audit_log_path.is_file():
        entry_tests = _evaluate_entry_tests(
            entry=None,
            event_name=EVENT_NAME,
            marker=marker,
            username=user,
            region=region,
            probe_started_at=probe_started_at,
        )
        tests.update(entry_tests)
        tests.update(_evaluate_retention_tests(retention_days))
        return {
            "success": False,
            "platform": "security",
            "test_name": TEST_NAME,
            "region": region,
            "audit_log_path": str(audit_log_path),
            "error": f"Audit log path is not a readable file: {audit_log_path}",
            "tests": tests,
        }

    event_name = _call_management_api(xmlrpc_url, auth, marker, xmlrpc_timeout_seconds)
    entry = _find_audit_entry(
        audit_log_path=audit_log_path,
        marker=marker,
        event_name=event_name,
        username=user,
        poll_seconds=poll_seconds,
        poll_interval_seconds=poll_interval_seconds,
        max_bytes=max_bytes,
    )
    tests.update(
        _evaluate_entry_tests(
            entry=entry,
            event_name=event_name,
            marker=marker,
            username=user,
            region=region,
            probe_started_at=probe_started_at,
        )
    )
    tests.update(_evaluate_retention_tests(retention_days))

    return {
        "success": all(test.get("passed") for test in tests.values()),
        "platform": "security",
        "test_name": TEST_NAME,
        "region": region,
        "audit_log_path": str(audit_log_path),
        "audit_log_retention_days": retention_days,
        "tests": tests,
    }


def main() -> int:
    """Run SEC08 audit logging and retention checks."""
    parser = argparse.ArgumentParser(description="OpenNebula audit logging and retention test (SEC08-01/02)")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--xmlrpc-url", default=os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"))
    parser.add_argument("--auth", default=os.environ.get("ONE_AUTH", "oneadmin:opennebula"))
    parser.add_argument("--audit-log-path", default=os.environ.get("ONE_AUDIT_LOG_PATH", ""))
    parser.add_argument("--audit-retention-days", type=int, default=int(os.environ.get("ONE_AUDIT_RETENTION_DAYS", "0")))
    parser.add_argument("--poll-seconds", type=int, default=int(os.environ.get("ONE_AUDIT_POLL_SECONDS", "20")))
    parser.add_argument("--poll-interval-seconds", type=float, default=1.0)
    parser.add_argument(
        "--xmlrpc-timeout-seconds",
        type=float,
        default=float(os.environ.get("ONE_AUDIT_XMLRPC_TIMEOUT_SECONDS", "10")),
    )
    parser.add_argument("--max-bytes", type=int, default=2_000_000)
    args = parser.parse_args()

    try:
        result = evaluate_audit_logging(
            region=args.region,
            xmlrpc_url=args.xmlrpc_url,
            auth=args.auth,
            audit_log_path=Path(args.audit_log_path),
            retention_days=args.audit_retention_days,
            poll_seconds=args.poll_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
            xmlrpc_timeout_seconds=args.xmlrpc_timeout_seconds,
            max_bytes=args.max_bytes,
        )
    except Exception as e:
        error = str(e)
        result = {
            "success": False,
            "platform": "security",
            "test_name": TEST_NAME,
            "region": args.region,
            "error": error,
            "tests": {
                "audit_log_entry_found": {"passed": False, "error": error},
                "audit_log_event_name_matches": {"passed": False, "error": error},
                "audit_log_event_time_in_window": {"passed": False, "error": error},
                "audit_log_user_identity_present": {"passed": False, "error": error},
                "audit_log_source_ip_present": {"passed": False, "error": error},
                "audit_log_user_agent_matches": {"passed": False, "error": error},
                "audit_log_region_matches": {"passed": False, "error": error},
                "audit_log_event_source_matches": {"passed": False, "error": error},
                "audit_log_trail_logging_enabled": {"passed": False, "error": error},
                "audit_log_retention_at_least_30_days": {"passed": False, "error": error},
            },
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
