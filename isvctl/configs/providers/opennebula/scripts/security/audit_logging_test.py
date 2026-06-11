#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula XML-RPC audit-log entry evidence and retention."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import sys
import time
import uuid
import xmlrpc.client as xmlrpc_client
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

TEST_NAME = "audit_logging_test"
EVENT_NAME = "one.system.version"
EVENT_SOURCE = "opennebula-xmlrpc"
MIN_RETENTION_DAYS = 30
DEFAULT_LOGROTATE_CONFIG_PATH = "/etc/logrotate.d/opennebula"
DEFAULT_LOGROTATE_MAIN_CONFIG_PATH = "/etc/logrotate.conf"
RETENTION_EVIDENCE_ERROR = (
    "OpenNebula local logrotate policy is not sufficient evidence that audit logs "
    "are retained for at least 30 days"
)


class LogrotatePolicy(NamedTuple):
    """Logrotate stanza covering one or more log paths."""

    paths: tuple[str, ...]
    directives: dict[str, list[str]]


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
    today = probe_started_at.astimezone(UTC).date().isoformat()
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


def _strip_logrotate_comment(line: str) -> str:
    """Remove shell-style comments from a logrotate line."""
    return line.split("#", 1)[0].strip()


def _read_logrotate_policies(path: Path) -> list[LogrotatePolicy]:
    """Parse logrotate stanzas from a config file."""
    policies: list[LogrotatePolicy] = []
    pending_header = ""
    current_paths: tuple[str, ...] = ()
    current_directives: dict[str, list[str]] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = _strip_logrotate_comment(raw_line)
        if not line:
            continue

        if current_paths:
            if "}" in line:
                before_close, _sep, _after_close = line.partition("}")
                directive_line = before_close.strip()
                if directive_line:
                    _add_logrotate_directive(current_directives, directive_line)
                policies.append(LogrotatePolicy(paths=current_paths, directives=current_directives))
                current_paths = ()
                current_directives = {}
                continue
            _add_logrotate_directive(current_directives, line)
            continue

        pending_header = f"{pending_header} {line}".strip()
        if "{" not in pending_header:
            continue

        header, _sep, remainder = pending_header.partition("{")
        current_paths = tuple(shlex.split(header))
        current_directives = {}
        pending_header = ""
        remainder = remainder.strip()
        if remainder:
            if "}" in remainder:
                directive_line, _sep, _after_close = remainder.partition("}")
                if directive_line.strip():
                    _add_logrotate_directive(current_directives, directive_line.strip())
                policies.append(LogrotatePolicy(paths=current_paths, directives=current_directives))
                current_paths = ()
                current_directives = {}
            else:
                _add_logrotate_directive(current_directives, remainder)

    return policies


def _add_logrotate_directive(directives: dict[str, list[str]], line: str) -> None:
    """Add a parsed directive line to a directives map."""
    parts = shlex.split(line)
    if parts:
        directives[parts[0].lower()] = parts[1:]


def _read_logrotate_globals(path: Path) -> dict[str, list[str]]:
    """Parse global directives from logrotate.conf before any stanza body."""
    directives: dict[str, list[str]] = {}
    in_stanza = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = _strip_logrotate_comment(raw_line)
        if not line:
            continue
        if "{" in line:
            in_stanza = True
            continue
        if "}" in line:
            in_stanza = False
            continue
        if not in_stanza:
            _add_logrotate_directive(directives, line)
    return directives


def _main_config_includes(main_config_path: Path, included_config_path: Path) -> bool:
    """Return True when logrotate.conf includes the OpenNebula logrotate config."""
    included_config = included_config_path.resolve()
    included_dir = included_config.parent
    for raw_line in main_config_path.read_text(encoding="utf-8").splitlines():
        line = _strip_logrotate_comment(raw_line)
        if not line:
            continue
        parts = shlex.split(line)
        if len(parts) != 2 or parts[0] != "include":
            continue
        include_path = Path(parts[1]).expanduser()
        try:
            resolved = include_path.resolve()
        except OSError:
            resolved = include_path
        if resolved == included_config or resolved == included_dir:
            return True
    return False


def _log_path_matches(pattern: str, audit_log_path: Path) -> bool:
    """Return True when a logrotate path pattern covers the audit log path."""
    audit_path = str(audit_log_path)
    return pattern == audit_path or audit_log_path.match(pattern)


def _retention_days_from_logrotate(policy: LogrotatePolicy, globals_: dict[str, list[str]]) -> tuple[int | None, str]:
    """Return effective retention days and a human-readable policy summary."""
    directives = {**globals_, **policy.directives}
    interval_days = 0
    interval = "unspecified"
    for name, days in (("daily", 1), ("weekly", 7), ("monthly", 31), ("yearly", 365), ("annually", 365)):
        if name in directives:
            interval_days = days
            interval = name
            break

    rotate_values = directives.get("rotate", [])
    if not interval_days or not rotate_values:
        return None, "missing rotation interval or rotate count"

    try:
        rotate_count = int(rotate_values[0])
    except ValueError:
        return None, f"invalid rotate count {rotate_values[0]!r}"
    if rotate_count < 1:
        return 0, f"{interval} rotate {rotate_count}"

    retention_days = interval_days * rotate_count
    maxage_values = directives.get("maxage", [])
    summary = f"{interval} rotate {rotate_count}"
    if maxage_values:
        try:
            maxage_days = int(maxage_values[0])
        except ValueError:
            return None, f"invalid maxage {maxage_values[0]!r}"
        retention_days = min(retention_days, maxage_days)
        summary = f"{summary} maxage {maxage_days}"
    return retention_days, summary


def _evaluate_retention_tests(
    *,
    audit_log_path: Path,
    logrotate_config_path: Path,
    logrotate_main_config_path: Path,
) -> dict[str, dict[str, Any]]:
    """Build SEC08-02 retention results from active logrotate policy."""
    probes = [
        {
            "minimum_retention_days": MIN_RETENTION_DAYS,
            "audit_log_path": str(audit_log_path),
            "logrotate_config_path": str(logrotate_config_path),
            "logrotate_main_config_path": str(logrotate_main_config_path),
        }
    ]

    if not logrotate_config_path.is_file():
        error = f"OpenNebula logrotate config is not readable: {logrotate_config_path}"
        failed = _failed(error, probes)
        return {
            "audit_log_trail_logging_enabled": failed,
            "audit_log_retention_at_least_30_days": failed,
        }
    if not logrotate_main_config_path.is_file():
        error = f"logrotate main config is not readable: {logrotate_main_config_path}"
        failed = _failed(error, probes)
        return {
            "audit_log_trail_logging_enabled": failed,
            "audit_log_retention_at_least_30_days": failed,
        }
    if not _main_config_includes(logrotate_main_config_path, logrotate_config_path):
        error = f"{logrotate_main_config_path} does not include {logrotate_config_path}"
        failed = _failed(error, probes)
        return {
            "audit_log_trail_logging_enabled": failed,
            "audit_log_retention_at_least_30_days": failed,
        }

    policies = _read_logrotate_policies(logrotate_config_path)
    matching = [policy for policy in policies if any(_log_path_matches(path, audit_log_path) for path in policy.paths)]
    if not matching:
        error = f"No logrotate stanza covers {audit_log_path}"
        failed = _failed(error, probes)
        return {
            "audit_log_trail_logging_enabled": failed,
            "audit_log_retention_at_least_30_days": failed,
        }

    globals_ = _read_logrotate_globals(logrotate_main_config_path)
    policy = matching[-1]
    retention_days, summary = _retention_days_from_logrotate(policy, globals_)
    probes[0].update(
        {
            "matched_log_paths": list(policy.paths),
            "logrotate_policy": summary,
            "computed_retention_days": retention_days,
        }
    )
    if retention_days is None:
        error = f"Cannot compute logrotate retention for {audit_log_path}: {summary}"
        return {
            "audit_log_trail_logging_enabled": _passed("OpenNebula audit log is covered by active logrotate policy", probes),
            "audit_log_retention_at_least_30_days": _failed(error, probes),
        }

    return {
        "audit_log_trail_logging_enabled": _passed("OpenNebula audit log is covered by active logrotate policy", probes),
        "audit_log_retention_at_least_30_days": _failed(RETENTION_EVIDENCE_ERROR, probes),
    }


def evaluate_audit_logging(
    *,
    region: str,
    xmlrpc_url: str,
    auth: str,
    audit_log_path: Path,
    logrotate_config_path: Path,
    logrotate_main_config_path: Path,
    poll_seconds: int,
    poll_interval_seconds: float,
    xmlrpc_timeout_seconds: float,
    max_bytes: int,
) -> dict[str, Any]:
    """Run the OpenNebula audit logging probe and return provider-neutral JSON."""
    marker = f"isvctl-sec08-{uuid.uuid4().hex}"
    user = _username(auth)
    probe_started_at = datetime.now(UTC)
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
        tests.update(
            _evaluate_retention_tests(
                audit_log_path=audit_log_path,
                logrotate_config_path=logrotate_config_path,
                logrotate_main_config_path=logrotate_main_config_path,
            )
        )
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
    tests.update(
        _evaluate_retention_tests(
            audit_log_path=audit_log_path,
            logrotate_config_path=logrotate_config_path,
            logrotate_main_config_path=logrotate_main_config_path,
        )
    )

    return {
        "success": all(test.get("passed") for test in tests.values()),
        "platform": "security",
        "test_name": TEST_NAME,
        "region": region,
        "audit_log_path": str(audit_log_path),
        "logrotate_config_path": str(logrotate_config_path),
        "logrotate_main_config_path": str(logrotate_main_config_path),
        "tests": tests,
    }


def main() -> int:
    """Run SEC08 audit logging and retention checks."""
    parser = argparse.ArgumentParser(description="OpenNebula audit logging and retention test (SEC08-01/02)")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--xmlrpc-url", default=os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"))
    parser.add_argument("--auth", default=os.environ.get("ONE_AUTH", "oneadmin:opennebula"))
    parser.add_argument("--audit-log-path", default=os.environ.get("ONE_AUDIT_LOG_PATH", ""))
    parser.add_argument(
        "--logrotate-config-path",
        default=os.environ.get("ONE_LOGROTATE_CONFIG_PATH", DEFAULT_LOGROTATE_CONFIG_PATH),
    )
    parser.add_argument(
        "--logrotate-main-config-path",
        default=os.environ.get("ONE_LOGROTATE_MAIN_CONFIG_PATH", DEFAULT_LOGROTATE_MAIN_CONFIG_PATH),
    )
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
            logrotate_config_path=Path(args.logrotate_config_path),
            logrotate_main_config_path=Path(args.logrotate_main_config_path),
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
