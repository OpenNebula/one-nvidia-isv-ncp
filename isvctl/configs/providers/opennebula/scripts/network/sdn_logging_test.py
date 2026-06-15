#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula VM monitoring evidence for SDN latency/performance logging."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.network import get_one_server, get_value  # noqa: E402

ASPECT_TESTS: dict[str, list[str]] = {
    "hardware_faults": [
        "logging_endpoint_reachable",
        "fault_event_source_queryable",
        "log_destination_configured",
        "event_schema_valid",
    ],
    "latency_perf": [
        "metrics_endpoint_reachable",
        "performance_metric_present",
        "packet_metric_present",
        "samples_recent",
    ],
    "audit_trail": [
        "audit_endpoint_reachable",
        "create_rule_logged",
        "modify_rule_logged",
        "delete_rule_logged",
        "audit_event_has_required_fields",
        "cleanup",
    ],
}

ASPECT_STEP_NAMES: dict[str, str] = {
    "hardware_faults": "sdn_hardware_fault_logging",
    "latency_perf": "sdn_latency_perf_logging",
    "audit_trail": "sdn_filter_audit_trail",
}

TELEMETRY_NAMESPACE = "OpenNebula/VM/MONITORING"
PERFORMANCE_METRICS = ("NETRX_BW", "NETTX_BW")
PACKET_METRICS = ("NETRX", "NETTX")
OPTIONAL_METRICS = ("CPU", "MEMORY", "CPU_FORECAST", "MEMORY_FORECAST", "NETRX_BW_FORECAST", "NETTX_BW_FORECAST")


def _passed(message: str, **extra: Any) -> dict[str, Any]:
    """Return a passing subtest result."""
    result: dict[str, Any] = {"passed": True, "message": message}
    result.update(extra)
    return result


def _failed(error: str, **extra: Any) -> dict[str, Any]:
    """Return a failing subtest result."""
    result: dict[str, Any] = {"passed": False, "error": error}
    result.update(extra)
    return result


def _base_result(aspect: str, network_id: str, region: str, vm_id: str) -> dict[str, Any]:
    """Build the standard SDN logging result envelope."""
    return {
        "success": False,
        "platform": "network",
        "test_name": ASPECT_STEP_NAMES[aspect],
        "region": region,
        "network_id": network_id,
        "aspect": aspect,
        "probe_resource_id": str(vm_id),
        "tests": {name: _failed("not run") for name in ASPECT_TESTS[aspect]},
    }


def _get_field(item: Any, key: str, default: Any = None) -> Any:
    """Read a dict key or object attribute, accepting common key casing."""
    value = get_value(item, key, None)
    if value is not None:
        return value

    if isinstance(item, dict):
        lowered = {str(item_key).lower(): item_value for item_key, item_value in item.items()}
        return lowered.get(key.lower(), default)

    for candidate in (key.upper(), key.lower()):
        value = getattr(item, candidate, None)
        if value is not None:
            return value

    return default


def _numeric_field(item: Any, key: str) -> float | None:
    """Return a monitoring field as a float when it is present and numeric."""
    value = _get_field(item, key)
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def _field_names(item: Any) -> list[str]:
    """Return visible monitoring field names for concise diagnostics."""
    if isinstance(item, dict):
        return sorted(str(key) for key in item)
    try:
        names = vars(item).keys()
    except TypeError:
        names = []
    return sorted(str(name) for name in names if not str(name).startswith("_"))


def _metric_snapshot(monitoring: Any) -> dict[str, float]:
    """Return validation-relevant numeric monitoring fields."""
    snapshot: dict[str, float] = {}
    for key in (*PERFORMANCE_METRICS, *PACKET_METRICS, *OPTIONAL_METRICS):
        value = _numeric_field(monitoring, key)
        if value is not None:
            snapshot[key] = value
    return snapshot


def _timestamp_age_seconds(monitoring: Any, now: float) -> tuple[int | None, float | None]:
    """Return the monitoring timestamp and sample age in seconds."""
    timestamp = _numeric_field(monitoring, "TIMESTAMP")
    if timestamp is None:
        return None, None
    timestamp_int = int(timestamp)
    return timestamp_int, round(now - timestamp, 2)


def _check_required_numeric_fields(monitoring: Any, field_names: tuple[str, ...]) -> tuple[bool, list[str]]:
    """Return whether all requested monitoring fields are numeric."""
    missing = [field for field in field_names if _numeric_field(monitoring, field) is None]
    return not missing, missing


def check_latency_perf_logging(
    one: Any,
    *,
    region: str,
    network_id: str,
    vm_id: str,
    sample_window_seconds: int,
    monitoring_wait_timeout: int,
    poll_interval_seconds: float,
) -> dict[str, Any]:
    """Validate OpenNebula VM monitoring fields used as performance telemetry."""
    result = _base_result("latency_perf", network_id, region, vm_id)
    result["telemetry_namespace"] = TELEMETRY_NAMESPACE
    result["sample_window_seconds"] = sample_window_seconds
    result["monitoring_wait_timeout"] = monitoring_wait_timeout

    if sample_window_seconds <= 0:
        error = "--sample-window-seconds must be greater than 0"
        for name in ASPECT_TESTS["latency_perf"]:
            result["tests"][name] = _failed(error)
        result["error"] = error
        return result
    if monitoring_wait_timeout < 0:
        error = "--monitoring-wait-timeout must be non-negative"
        for name in ASPECT_TESTS["latency_perf"]:
            result["tests"][name] = _failed(error)
        result["error"] = error
        return result
    if poll_interval_seconds <= 0:
        error = "--poll-interval-seconds must be greater than 0"
        for name in ASPECT_TESTS["latency_perf"]:
            result["tests"][name] = _failed(error)
        result["error"] = error
        return result

    deadline = time.monotonic() + monitoring_wait_timeout
    attempt = 0

    while True:
        attempt += 1
        result["monitoring_attempts"] = attempt
        try:
            vm_info = one.vm.info(int(vm_id))
        except Exception as e:
            error = f"Could not inspect OpenNebula VM {vm_id}: {e}"
            for name in ASPECT_TESTS["latency_perf"]:
                result["tests"][name] = _failed(error)
            result["error"] = error
        else:
            monitoring = _get_field(vm_info, "MONITORING")
            if monitoring is None:
                error = f"VM {vm_id} has no MONITORING section"
                result["tests"]["metrics_endpoint_reachable"] = _failed(error)
                for name in ("performance_metric_present", "packet_metric_present", "samples_recent"):
                    result["tests"][name] = _failed(error)
                result["error"] = error
            else:
                fields = _field_names(monitoring)
                result["metric_values"] = _metric_snapshot(monitoring)
                result["tests"]["metrics_endpoint_reachable"] = _passed(
                    "OpenNebula VM monitoring endpoint returned MONITORING data",
                    monitoring_fields=fields,
                )

                perf_ok, missing_perf = _check_required_numeric_fields(monitoring, PERFORMANCE_METRICS)
                result["tests"]["performance_metric_present"] = (
                    _passed(
                        "OpenNebula network bandwidth metrics are present",
                        metrics={field: result["metric_values"][field] for field in PERFORMANCE_METRICS},
                    )
                    if perf_ok
                    else _failed(
                        f"Missing numeric OpenNebula performance metric(s): {missing_perf}",
                        monitoring_fields=fields,
                    )
                )

                packet_ok, missing_packet = _check_required_numeric_fields(monitoring, PACKET_METRICS)
                result["tests"]["packet_metric_present"] = (
                    _passed(
                        "OpenNebula network byte counters are present",
                        metrics={field: result["metric_values"][field] for field in PACKET_METRICS},
                    )
                    if packet_ok
                    else _failed(
                        f"Missing numeric OpenNebula packet/counter metric(s): {missing_packet}",
                        monitoring_fields=fields,
                    )
                )

                timestamp, age_seconds = _timestamp_age_seconds(monitoring, time.time())
                result["monitoring_timestamp"] = timestamp
                result["sample_age_seconds"] = age_seconds
                result["tests"]["samples_recent"] = (
                    _passed(
                        "OpenNebula monitoring sample is recent",
                        timestamp=timestamp,
                        age_seconds=age_seconds,
                        sample_window_seconds=sample_window_seconds,
                    )
                    if timestamp is not None and age_seconds is not None and age_seconds <= sample_window_seconds
                    else _failed(
                        "OpenNebula monitoring sample is missing or stale",
                        timestamp=timestamp,
                        age_seconds=age_seconds,
                        sample_window_seconds=sample_window_seconds,
                    )
                )

                if all(test.get("passed") for test in result["tests"].values()):
                    break

        if time.monotonic() >= deadline:
            break
        time.sleep(poll_interval_seconds)

    result["success"] = all(test.get("passed") for test in result["tests"].values())
    result["status"] = "passed" if result["success"] else "failed"
    if result["success"]:
        result.pop("error", None)
    else:
        result["error"] = "SDN latency/performance logging checks failed"
    return result


def _standby_result(aspect: str, network_id: str, region: str, vm_id: str) -> dict[str, Any]:
    """Return an explicit failure for standby SDN logging aspects."""
    result = _base_result(aspect, network_id, region, vm_id)
    error = f"OpenNebula {aspect} SDN logging adaptation is in standby"
    for name in ASPECT_TESTS[aspect]:
        result["tests"][name] = _failed(error)
    result["error"] = error
    result["status"] = "failed"
    return result


def run_aspect(args: argparse.Namespace) -> dict[str, Any]:
    """Dispatch an OpenNebula SDN logging aspect."""
    if args.aspect != "latency_perf":
        return _standby_result(args.aspect, args.network_id, args.region, args.vm_id)

    one = get_one_server(args.xmlrpc_url, args.auth)
    return check_latency_perf_logging(
        one,
        region=args.region,
        network_id=args.network_id,
        vm_id=args.vm_id,
        sample_window_seconds=args.sample_window_seconds,
        monitoring_wait_timeout=args.monitoring_wait_timeout,
        poll_interval_seconds=args.poll_interval_seconds,
    )


def main() -> int:
    """Run an OpenNebula SDN logging validation aspect and emit JSON."""
    parser = argparse.ArgumentParser(description="SDN logging validation (OpenNebula)")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--vpc-id", "--network-id", dest="network_id", required=True, help="Virtual network ID")
    parser.add_argument("--vm-id", required=True, help="VM ID whose MONITORING data will be inspected")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--aspect", required=True, choices=sorted(ASPECT_TESTS), help="SDN logging aspect to test")
    parser.add_argument(
        "--sample-window-seconds",
        type=int,
        default=900,
        help="Maximum age of MONITORING.TIMESTAMP accepted as recent",
    )
    parser.add_argument(
        "--monitoring-wait-timeout",
        type=int,
        default=300,
        help="Seconds to wait for OpenNebula VM.MONITORING metrics to appear",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=float,
        default=10.0,
        help="Seconds between VM.MONITORING polling attempts",
    )
    args = parser.parse_args()

    try:
        result = run_aspect(args)
    except Exception as e:
        result = _base_result(args.aspect, args.network_id, args.region, args.vm_id)
        error = str(e)
        for name in ASPECT_TESTS[args.aspect]:
            result["tests"][name] = _failed(error)
        result["error"] = error
        result["status"] = "failed"

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
