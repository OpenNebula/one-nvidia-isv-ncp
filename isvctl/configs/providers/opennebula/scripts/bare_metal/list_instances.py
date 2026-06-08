#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""List OpenNebula NICo bare-metal instances."""

import argparse
import json
import os
import sys
from typing import Any

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


def get_value(item: Any, key: str, default: Any = None) -> Any:
    """Return a value from a dict-like or attribute-based pyone object."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def as_int(value: Any) -> int | None:
    """Convert OpenNebula numeric fields to int when possible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def map_state(vm_info: Any) -> str:
    """Map OpenNebula VM states to provider-neutral instance states."""
    state = as_int(get_value(vm_info, "STATE"))
    lcm_state = as_int(get_value(vm_info, "LCM_STATE"))

    if state == 3 and lcm_state == 3:
        return "running"
    if state in {0, 1, 2, 10} or state == 3:
        return "pending"
    if state in {4, 5, 8, 9}:
        return "stopped"
    if state == 6:
        return "terminated"
    if state in {7, 11}:
        return "failed"
    return "unknown"


def main() -> int:
    """List the target OpenNebula VM as a bare-metal instance."""
    parser = argparse.ArgumentParser(description="List OpenNebula bare-metal instances")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "instances": [],
        "count": 0,
        "found_target": False,
        "target_instance": str(args.instance_id),
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        vm_info = one.vm.info(args.instance_id)
        deploy_id = str(get_value(vm_info, "DEPLOY_ID", "") or "")

        instance = {
            "instance_id": str(args.instance_id),
            "deploy_id": deploy_id,
            "name": str(get_value(vm_info, "NAME", "") or ""),
            "state": map_state(vm_info),
            "vpc_id": "opennebula",
        }

        result["instances"] = [instance]
        result["count"] = 1
        result["found_target"] = True
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
