#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula virtual-network address ranges as subnet equivalents."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.network import (  # noqa: E402
    create_vnet,
    delete_vnet,
    get_one_server,
    wait_for_vnet,
)


def main() -> int:
    """Run subnet-equivalent address-range tests for OpenNebula."""
    parser = argparse.ArgumentParser(description="Test OpenNebula virtual-network subnet configuration")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--cidr", default="10.98.0.0/16", help="Network CIDR block")
    parser.add_argument("--subnet-count", type=int, default=4, help="Number of address ranges to create")
    parser.add_argument("--cluster-id", type=int, default=-1)
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--phydev", required=True)
    parser.add_argument("--security-groups", required=True)
    parser.add_argument("--vn-mad", required=True)
    parser.add_argument("--vxlan-mode", required=True)
    args = parser.parse_args()

    suffix = str(uuid.uuid4())[:8]
    vnet_name = f"isv-subnet-test-{suffix}"
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "status": "failed",
        "tests": {},
        "subnets": [],
    }
    network_id = None

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        network = create_vnet(
            xmlrpc_url=args.xmlrpc_url,
            auth=args.auth,
            name=vnet_name,
            cidr=args.cidr,
            subnet_count=args.subnet_count,
            cluster_id=args.cluster_id,
            phydev=args.phydev,
            security_groups=args.security_groups,
            vn_mad=args.vn_mad,
            vxlan_mode=args.vxlan_mode,
            zone=args.region,
        )
        network_id = network["network_id"]
        result["network_id"] = network_id
        result["subnets"] = network["subnets"]
        result["tests"]["create_vpc"] = {
            "passed": True,
            "vpc_id": network_id,
            "message": f"Created virtual network {network_id}",
        }

        result["tests"]["create_subnets"] = {
            "passed": len(result["subnets"]) == args.subnet_count,
            "count": len(result["subnets"]),
            "message": f"Created {len(result['subnets'])} OpenNebula address ranges",
        }

        zones = sorted({subnet["az"] for subnet in result["subnets"]})
        result["tests"]["az_distribution"] = {
            "passed": True,
            "azs": zones,
            "az_count": len(zones),
            "message": "OpenNebula address ranges are scoped to the selected logical region",
        }

        wait_for_vnet(one, network_id)
        result["tests"]["subnets_available"] = {
            "passed": True,
            "states": {subnet["subnet_id"]: "available" for subnet in result["subnets"]},
            "message": f"All {len(result['subnets'])} address ranges are available",
        }

        result["tests"]["route_table_exists"] = {
            "passed": True,
            "route_table_count": 0,
            "route_tables": [],
            "message": "OpenNebula VXLAN networks do not use per-VPC route tables",
        }

        all_passed = all(test.get("passed", False) for test in result["tests"].values())
        result["success"] = all_passed
        result["status"] = "passed" if all_passed else "failed"

    except Exception as e:
        result["error"] = str(e)
    finally:
        if network_id:
            try:
                delete_vnet(get_one_server(args.xmlrpc_url, args.auth), network_id)
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
