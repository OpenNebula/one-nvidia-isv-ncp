#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Measure OpenNebula security group policy propagation through API visibility."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.network import (  # noqa: E402
    allocate_security_group,
    allow_all_egress_rule,
    build_sg_template,
    delete_security_group,
    get_one_server,
    tcp_rule,
    update_security_group,
    wait_for_security_group_rule_state,
)

TEST_NAMES = [
    "create_probe_rule",
    "rule_observed",
    "revoke_probe_rule",
    "removal_observed",
    "cleanup",
]
DEFAULT_MAX_PROPAGATION_SECONDS = 10.0
DEFAULT_POLL_SECONDS = 0.5
PROBE_CIDR = "10.0.0.0/8"
PROBE_PORT = 443


def _passed(message: str = "", **extra: Any) -> dict[str, Any]:
    """Return a passing subtest result."""
    result: dict[str, Any] = {"passed": True}
    if message:
        result["message"] = message
    result.update(extra)
    return result


def _failed(error: str, **extra: Any) -> dict[str, Any]:
    """Return a failing subtest result."""
    result: dict[str, Any] = {"passed": False, "error": error}
    result.update(extra)
    return result


def _base_result(max_propagation_seconds: float, network_id: str) -> dict[str, Any]:
    """Build the result envelope with subtests initialized to failed."""
    return {
        "success": False,
        "platform": "network",
        "test_name": "sg_policy_propagation",
        "status": "failed",
        "network_id": network_id,
        "max_propagation_seconds": max_propagation_seconds,
        "tests": {name: {"passed": False} for name in TEST_NAMES},
    }


def main() -> int:
    """Run the OpenNebula policy propagation timing probe."""
    parser = argparse.ArgumentParser(description="Measure OpenNebula security policy propagation timing")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--vpc-id", "--network-id", dest="network_id", required=True, help="Target network ID")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument(
        "--max-propagation-seconds",
        type=float,
        default=DEFAULT_MAX_PROPAGATION_SECONDS,
        help="Maximum acceptable add/remove propagation time",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=DEFAULT_POLL_SECONDS,
        help="Polling interval while waiting for policy state changes",
    )
    args = parser.parse_args()

    result = _base_result(args.max_propagation_seconds, str(args.network_id))
    suffix = uuid.uuid4().hex[:8]
    sg_name = f"isv-sdn-policy-propagation-{suffix}"
    description = "ISV policy propagation probe"
    probe_rule = tcp_rule("INBOUND", PROBE_PORT, PROBE_CIDR)
    one = None
    sg_id = None
    failed_key = "create_probe_rule"

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        try:
            one.vn.info(int(args.network_id))
        except Exception as e:
            raise RuntimeError(f"Target virtual network {args.network_id} was not found") from e

        sg_id = allocate_security_group(one, build_sg_template(sg_name, description, [allow_all_egress_rule()]))
        result["target_rule_id"] = sg_id

        update_security_group(
            one,
            sg_id,
            build_sg_template(sg_name, description, [allow_all_egress_rule(), probe_rule]),
        )
        result["tests"]["create_probe_rule"] = _passed("Probe rule added")

        failed_key = "rule_observed"
        observed, add_seconds = wait_for_security_group_rule_state(
            one,
            sg_id,
            expected_present=True,
            protocol="TCP",
            rule_type="INBOUND",
            port=PROBE_PORT,
            cidr=PROBE_CIDR,
            timeout=args.max_propagation_seconds,
            interval=args.poll_seconds,
        )
        result["add_observed_seconds"] = round(add_seconds, 3)
        if not observed:
            result["tests"]["rule_observed"] = _failed(
                f"Probe rule was not observable within {args.max_propagation_seconds:.2f}s",
                propagation_timeout=True,
                seconds=round(add_seconds, 3),
            )
            return 1
        result["tests"]["rule_observed"] = _passed(
            f"Probe rule observable after {add_seconds:.2f}s",
            seconds=round(add_seconds, 3),
        )

        failed_key = "revoke_probe_rule"
        update_security_group(one, sg_id, build_sg_template(sg_name, description, [allow_all_egress_rule()]))
        result["tests"]["revoke_probe_rule"] = _passed("Probe rule removed")

        failed_key = "removal_observed"
        removed, remove_seconds = wait_for_security_group_rule_state(
            one,
            sg_id,
            expected_present=False,
            protocol="TCP",
            rule_type="INBOUND",
            port=PROBE_PORT,
            cidr=PROBE_CIDR,
            timeout=args.max_propagation_seconds,
            interval=args.poll_seconds,
        )
        result["remove_observed_seconds"] = round(remove_seconds, 3)
        if not removed:
            result["tests"]["removal_observed"] = _failed(
                f"Probe rule removal was not observable within {args.max_propagation_seconds:.2f}s",
                propagation_timeout=True,
                seconds=round(remove_seconds, 3),
            )
            return 1
        result["tests"]["removal_observed"] = _passed(
            f"Probe rule removal observable after {remove_seconds:.2f}s",
            seconds=round(remove_seconds, 3),
        )

    except Exception as e:
        result["tests"][failed_key] = _failed(str(e))
        result["error"] = str(e)
    finally:
        if one and sg_id:
            try:
                delete_security_group(one, sg_id)
                result["tests"]["cleanup"] = _passed("Probe security group deleted")
            except Exception as e:
                result["tests"]["cleanup"] = _failed(str(e))
        else:
            result["tests"]["cleanup"] = _passed("No probe security group was created")

        result["success"] = all(test.get("passed") for test in result["tests"].values())
        result["status"] = "passed" if result["success"] else "failed"
        if not result["success"] and "error" not in result:
            result["error"] = "Security policy propagation timing checks failed"

        print(json.dumps(result, indent=2))

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
