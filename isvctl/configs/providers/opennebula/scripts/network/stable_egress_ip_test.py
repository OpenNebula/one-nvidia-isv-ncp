#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test stable egress IP by reusing the DHCP/IP validation VM."""

from __future__ import annotations

import argparse
import ipaddress
import json
import shlex
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_connectivity import ssh_run, wait_for_ssh  # noqa: E402

TEST_NAME = "stable_egress_ip"
STABLE_EGRESS_TESTS = ("create_instance", "probe_egress_ip", "egress_ip_stable")


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


def _probe_egress_ip(args: argparse.Namespace) -> dict[str, Any]:
    """Probe the external egress IP through SSH."""
    if not wait_for_ssh(args.ssh_host, args.ssh_user, args.key_file, args.ssh_wait_timeout):
        return _failed(f"SSH not reachable on {args.ssh_host}", probes=args.probes, endpoint=args.endpoint)

    ips = []
    quoted_endpoint = shlex.quote(args.endpoint)
    command = f"curl -fsS --max-time 5 {quoted_endpoint} || wget -q -T 5 -O - {quoted_endpoint}"

    for attempt in range(1, args.probes + 1):
        if attempt > 1:
            time.sleep(args.interval_seconds)
        exit_code, stdout, stderr = ssh_run(
            args.ssh_host,
            args.ssh_user,
            args.key_file,
            command,
            timeout=args.ssh_command_timeout,
        )
        if exit_code != 0:
            return _failed(
                f"probe {attempt}/{args.probes} failed",
                probes=args.probes,
                endpoint=args.endpoint,
                details=(stderr or stdout or f"command exited with {exit_code}").strip(),
                ips=ips,
            )
        ip = stdout.strip().splitlines()[-1].strip() if stdout.strip() else ""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return _failed(
                f"probe {attempt}/{args.probes} returned non-IP value",
                probes=args.probes,
                endpoint=args.endpoint,
                value=ip,
                ips=ips,
            )
        ips.append(ip)

    return _passed(
        f"Collected {len(ips)} egress IP probes",
        probes=args.probes,
        endpoint=args.endpoint,
        ips=ips,
    )


def run_stable_egress_ip_test(args: argparse.Namespace) -> dict[str, Any]:
    """Run stable egress IP checks against an existing VM."""
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": TEST_NAME,
        "status": "failed",
        "tests": {name: _failed("not run") for name in STABLE_EGRESS_TESTS},
    }

    try:
        if not args.instance_id:
            raise RuntimeError("--instance-id is required")
        if not args.ssh_host:
            raise RuntimeError("--ssh-host is required")
        if not args.key_file:
            raise RuntimeError("--key-file is required")
        if args.probes < 1:
            raise RuntimeError("--probes must be at least 1")

        result["tests"]["create_instance"] = _passed(
            "Reusing DHCP/IP validation VM",
            instance_id=str(args.instance_id),
            ssh_host=args.ssh_host,
        )

        probe_result = _probe_egress_ip(args)
        result["tests"]["probe_egress_ip"] = probe_result
        if not probe_result.get("passed"):
            raise RuntimeError(probe_result.get("error", "Egress IP probing failed"))

        ips = probe_result.get("ips", [])
        distinct = sorted(set(ips))
        result["tests"]["egress_ip_stable"] = (
            _passed("Egress IP stable across probes", ip=distinct[0], distinct=len(distinct), probes=args.probes)
            if len(distinct) == 1
            else _failed("Egress IP changed across probes", ips=ips, distinct_ips=distinct, probes=args.probes)
        )

    except Exception as e:
        result["error"] = str(e)
        for name, test in result["tests"].items():
            if not test.get("passed") and test.get("error") == "not run":
                result["tests"][name] = _failed(str(e))
                break

    result["success"] = all(test.get("passed", False) for test in result["tests"].values())
    result["status"] = "passed" if result["success"] else "failed"
    return result


def main() -> int:
    """Run OpenNebula stable egress IP validation."""
    parser = argparse.ArgumentParser(description="Test stable egress IP from an existing OpenNebula VM")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--instance-id", required=True, help="Existing VM ID to probe")
    parser.add_argument("--ssh-host", required=True, help="SSH target IP/host for the VM")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument("--endpoint", default="https://api.ipify.org", help="External IP echo endpoint")
    parser.add_argument("--probes", type=int, default=3, help="Number of egress IP probes")
    parser.add_argument("--interval-seconds", type=float, default=2.0, help="Delay between probes")
    parser.add_argument("--ssh-wait-timeout", type=int, default=300, help="Seconds to wait for SSH access")
    parser.add_argument("--ssh-command-timeout", type=int, default=30, help="Seconds allowed for SSH commands")
    args = parser.parse_args()

    result = run_stable_egress_ip_test(args)
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
