#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Tear down an OpenNebula virtual network."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.network import delete_vnet, get_one_server, vnet_exists  # noqa: E402


def main() -> int:
    """Delete the shared OpenNebula network created during setup."""
    parser = argparse.ArgumentParser(description="Delete OpenNebula virtual network")
    parser.add_argument("--vpc-id", "--network-id", dest="network_id", required=True, help="Virtual network ID")
    parser.add_argument("--region", default="opennebula", help="Logical region label")
    parser.add_argument("--skip-destroy", action="store_true", help="Skip deletion")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "network_id": str(args.network_id),
        "region": args.region,
        "resources_deleted": [],
        "resources_failed": [],
    }

    if args.skip_destroy:
        result["success"] = True
        result["message"] = "Skipped virtual network deletion"
        print(json.dumps(result, indent=2))
        return 0

    try:
        one = get_one_server()
        if vnet_exists(one, args.network_id):
            delete_vnet(one, args.network_id)
            result["resources_deleted"].append(f"vnet:{args.network_id}")
        result["success"] = True
        result["message"] = "OpenNebula virtual network deleted"
    except Exception as e:
        result["error"] = str(e)
        result["resources_failed"].append(f"vnet:{args.network_id}")

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
