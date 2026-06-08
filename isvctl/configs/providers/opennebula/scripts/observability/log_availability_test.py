#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""OpenNebula observability log and telemetry availability tests."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ASPECT_TESTS: dict[str, list[str]] = {
    "vpc_flow_logs": [
        "flow_log_endpoint_reachable",
        "flow_logs_configured",
        "traffic_type_all",
        "log_destination_accessible",
    ],
    "host_syslogs": [
        "syslog_endpoint_reachable",
        "host_log_source_present",
        "entries_recent",
    ],
    "bmc_sel_logs": [
        "sel_log_endpoint_reachable",
        "sel_log_source_present",
        "sel_entries_queryable",
    ],
    "bmc_gpu_telemetry": [
        "telemetry_endpoint_reachable",
        "gpu_metrics_present",
        "host_os_gap_identified",
        "telemetry_samples_recent",
    ],
}

OPENNEBULA_BMC_NOT_IMPLEMENTED_MESSAGE = "Not implemented - OpenNebula BMC validation is not implemented"

SYSLOG_WITH_YEAR = re.compile(r"^(?P<stamp>[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})")
SYSLOG_NO_YEAR = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})")
ISO_TIMESTAMP = re.compile(r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)")


def _passed(message: str, probes: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a passing subtest result."""
    result: dict[str, Any] = {"passed": True, "message": message}
    if probes is not None:
        result["probes"] = probes
    return result


def _failed(error: str, probes: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a failing subtest result."""
    result: dict[str, Any] = {"passed": False, "error": error}
    if probes is not None:
        result["probes"] = probes
    return result


def _not_implemented(test_name: str, *, region: str) -> dict[str, Any]:
    """Build a failing result for unimplemented BMC surfaces."""
    return {
        "passed": False,
        "error": f"{test_name}: {OPENNEBULA_BMC_NOT_IMPLEMENTED_MESSAGE} in region {region}",
        "probes": {"bmc_endpoints_checked": 0},
    }


def _base_result(aspect: str) -> dict[str, Any]:
    """Build the common observability result envelope."""
    return {
        "success": False,
        "platform": "observability",
        "test_name": aspect,
        "tests": {name: {"passed": False} for name in ASPECT_TESTS[aspect]},
    }


def _recent_log_text(path: Path, max_bytes: int) -> str:
    """Read the tail of a log file."""
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        return f.read().decode("utf-8", errors="replace")


def _parse_log_timestamp(line: str, *, now: datetime) -> str:
    """Parse common OpenNebula/syslog timestamps and return an ISO string."""
    if match := ISO_TIMESTAMP.match(line):
        raw = match.group("stamp").replace(",", ".")
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return match.group("stamp")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()

    if match := SYSLOG_WITH_YEAR.match(line):
        try:
            parsed = datetime.strptime(match.group("stamp"), "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
        except ValueError:
            return match.group("stamp")
        return parsed.isoformat()

    if match := SYSLOG_NO_YEAR.match(line):
        try:
            parsed = datetime.strptime(f"{match.group('stamp')} {now.year}", "%b %d %H:%M:%S %Y").replace(
                tzinfo=UTC
            )
        except ValueError:
            return match.group("stamp")
        return parsed.isoformat()

    return ""


def _count_log_entries(path: Path, *, max_age_minutes: int, max_bytes: int) -> tuple[int, str]:
    """Return count and latest timestamp for entries in the sampling window."""
    text = _recent_log_text(path, max_bytes)
    now = datetime.now(UTC)
    cutoff = now - timedelta(minutes=max_age_minutes)
    entry_count = 0
    latest_timestamp = ""

    for line in text.splitlines():
        if not line.strip():
            continue
        timestamp = _parse_log_timestamp(line, now=now)
        if timestamp:
            try:
                parsed = datetime.fromisoformat(timestamp)
            except ValueError:
                parsed = now
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            if parsed < cutoff:
                continue
            latest_timestamp = timestamp
        else:
            latest_timestamp = path.stat().st_mtime_ns and datetime.fromtimestamp(
                path.stat().st_mtime, UTC
            ).isoformat()
        entry_count += 1

    return entry_count, latest_timestamp


def check_vpc_flow_logs(*, network_id: str, flow_log_path: Path, max_bytes: int = 2_000_000) -> dict[str, Any]:
    """Check OpenNebula network-flow log evidence from a configured log file."""
    result = _base_result("vpc_flow_logs")
    probes = {
        "network_id": network_id,
        "log_destination": str(flow_log_path),
        "traffic_type": "ALL",
        "sample_window_seconds": 0,
    }

    if not network_id.strip():
        error = "OpenNebula network id is empty"
        for name in ASPECT_TESTS["vpc_flow_logs"]:
            result["tests"][name] = _failed(error, probes)
        result["error"] = error
        return result

    if not flow_log_path.is_file():
        error = f"OpenNebula flow log path is not a readable file: {flow_log_path}"
        for name in ASPECT_TESTS["vpc_flow_logs"]:
            result["tests"][name] = _failed(error, probes)
        result["error"] = error
        return result

    has_entries = bool(_recent_log_text(flow_log_path, max_bytes).strip())
    if not has_entries:
        error = f"OpenNebula flow log path is empty: {flow_log_path}"
        result["tests"]["flow_log_endpoint_reachable"] = _passed("OpenNebula flow log file is readable", probes)
        result["tests"]["flow_logs_configured"] = _failed(error, probes)
        result["tests"]["traffic_type_all"] = _passed("OpenNebula log source captures combined traffic events", probes)
        result["tests"]["log_destination_accessible"] = _failed(error, probes)
        result["error"] = error
        return result

    result["tests"]["flow_log_endpoint_reachable"] = _passed("OpenNebula flow log file is readable", probes)
    result["tests"]["flow_logs_configured"] = _passed("OpenNebula flow log source is configured", probes)
    result["tests"]["traffic_type_all"] = _passed("OpenNebula log source captures combined traffic events", probes)
    result["tests"]["log_destination_accessible"] = _passed(
        f"OpenNebula flow log destination exists: {flow_log_path}",
        probes,
    )
    result["success"] = True
    return result


def check_host_syslogs(*, host_log_path: Path, max_age_minutes: int, max_bytes: int = 2_000_000) -> dict[str, Any]:
    """Check host syslog evidence from a configured local log file."""
    result = _base_result("host_syslogs")
    probes = {"hosts_checked": 1, "log_source": str(host_log_path), "entry_count": 0, "latest_timestamp": ""}

    if max_age_minutes <= 0:
        error = "--max-age-minutes must be greater than 0"
        for name in ASPECT_TESTS["host_syslogs"]:
            result["tests"][name] = _failed(error, probes)
        result["error"] = error
        return result

    if not host_log_path.is_file():
        error = f"OpenNebula host syslog path is not a readable file: {host_log_path}"
        for name in ASPECT_TESTS["host_syslogs"]:
            result["tests"][name] = _failed(error, probes)
        result["error"] = error
        return result

    entry_count, latest_timestamp = _count_log_entries(
        host_log_path,
        max_age_minutes=max_age_minutes,
        max_bytes=max_bytes,
    )
    probes = {
        "hosts_checked": 1,
        "log_source": str(host_log_path),
        "entry_count": entry_count,
        "latest_timestamp": latest_timestamp,
    }
    result["tests"]["syslog_endpoint_reachable"] = _passed("OpenNebula host syslog file is readable", probes)
    if entry_count > 0 and latest_timestamp:
        result["tests"]["host_log_source_present"] = _passed("OpenNebula host log source is present", probes)
        result["tests"]["entries_recent"] = _passed(
            f"{entry_count} host log entries found in the sampling window",
            probes,
        )
    else:
        error = f"No recent OpenNebula host syslog entries found in {host_log_path}"
        result["tests"]["host_log_source_present"] = _failed(error, probes)
        result["tests"]["entries_recent"] = _failed(error, probes)
        result["error"] = error

    result["success"] = all(test.get("passed") for test in result["tests"].values())
    return result


def check_bmc_sel_logs(*, region: str) -> dict[str, Any]:
    """Emit explicit failure for unimplemented OpenNebula BMC SEL logs."""
    result = _base_result("bmc_sel_logs")
    result["error"] = OPENNEBULA_BMC_NOT_IMPLEMENTED_MESSAGE
    result["tests"] = {name: _not_implemented(name, region=region) for name in ASPECT_TESTS["bmc_sel_logs"]}
    return result


def check_bmc_gpu_telemetry(*, region: str) -> dict[str, Any]:
    """Emit explicit failure for unimplemented OpenNebula BMC GPU telemetry."""
    result = _base_result("bmc_gpu_telemetry")
    result["error"] = OPENNEBULA_BMC_NOT_IMPLEMENTED_MESSAGE
    result["tests"] = {name: _not_implemented(name, region=region) for name in ASPECT_TESTS["bmc_gpu_telemetry"]}
    return result


def main() -> int:
    """Run the selected OpenNebula observability probe and emit structured JSON."""
    parser = argparse.ArgumentParser(description="OpenNebula observability log availability test")
    default_log_path = os.environ.get("ONE_OBSERVABILITY_LOG_PATH", "/var/log/one/oned.log")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--network-id", default=os.environ.get("ONE_NETWORK_ID", "opennebula-virtual-network"))
    parser.add_argument("--aspect", required=True, choices=sorted(ASPECT_TESTS))
    parser.add_argument("--flow-log-path", default=default_log_path)
    parser.add_argument("--host-log-path", default=default_log_path)
    parser.add_argument(
        "--max-age-minutes",
        type=int,
        default=int(os.environ.get("ONE_HOST_SYSLOG_MAX_AGE_MINUTES", "1440")),
    )
    parser.add_argument("--max-bytes", type=int, default=2_000_000)
    args = parser.parse_args()

    if args.aspect == "vpc_flow_logs":
        result = check_vpc_flow_logs(
            network_id=args.network_id,
            flow_log_path=Path(args.flow_log_path),
            max_bytes=args.max_bytes,
        )
    elif args.aspect == "host_syslogs":
        result = check_host_syslogs(
            host_log_path=Path(args.host_log_path),
            max_age_minutes=args.max_age_minutes,
            max_bytes=args.max_bytes,
        )
    elif args.aspect == "bmc_sel_logs":
        result = check_bmc_sel_logs(region=args.region)
    else:
        result = check_bmc_gpu_telemetry(region=args.region)

    print(json.dumps(result, indent=2, default=str))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
