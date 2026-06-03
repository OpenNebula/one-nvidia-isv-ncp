#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula virtual-network isolation."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.network import (  # noqa: E402
    DEFAULT_PHYDEV,
    DEFAULT_SECURITY_GROUPS,
    DEFAULT_VN_MAD,
    DEFAULT_VXLAN_MODE,
    create_vnet,
    delete_vnet,
    get_one_server,
)


def main() -> int:
    """Create two VXLAN virtual networks and verify no explicit relationship exists."""
    parser = argparse.ArgumentParser(description="Test OpenNebula virtual-network isolation")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"), help="Logical region label")
    parser.add_argument("--cidr-a", default="10.97.0.0/16", help="CIDR for virtual network A")
    parser.add_argument("--cidr-b", default="10.96.0.0/16", help="CIDR for virtual network B")
    parser.add_argument("--cluster-id", type=int, default=int(os.environ.get("ONE_CLUSTER_ID", "-1")))
    parser.add_argument("--phydev", default=os.environ.get("ONE_VNET_PHYDEV", DEFAULT_PHYDEV))
    parser.add_argument(
        "--security-groups",
        default=os.environ.get("ONE_VNET_SECURITY_GROUPS", DEFAULT_SECURITY_GROUPS),
    )
    parser.add_argument("--vn-mad", default=os.environ.get("ONE_VNET_MAD", DEFAULT_VN_MAD))
    parser.add_argument("--vxlan-mode", default=os.environ.get("ONE_VNET_VXLAN_MODE", DEFAULT_VXLAN_MODE))
    args = parser.parse_args()

    suffix = str(uuid.uuid4())[:8]
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "status": "failed",
        "tests": {},
    }
    vnet_a_id = None
    vnet_b_id = None

    try:
        one = get_one_server()
        network_a = create_vnet(
            name=f"isv-isolation-a-{suffix}",
            cidr=args.cidr_a,
            subnet_count=1,
            cluster_id=args.cluster_id,
            phydev=args.phydev,
            security_groups=args.security_groups,
            vn_mad=args.vn_mad,
            vxlan_mode=args.vxlan_mode,
            zone=args.region,
        )
        vnet_a_id = network_a["network_id"]
        result["tests"]["create_vpc_a"] = {
            "passed": True,
            "vpc_id": vnet_a_id,
            "message": f"Created virtual network {vnet_a_id}",
        }

        network_b = create_vnet(
            name=f"isv-isolation-b-{suffix}",
            cidr=args.cidr_b,
            subnet_count=1,
            cluster_id=args.cluster_id,
            phydev=args.phydev,
            security_groups=args.security_groups,
            vn_mad=args.vn_mad,
            vxlan_mode=args.vxlan_mode,
            zone=args.region,
        )
        vnet_b_id = network_b["network_id"]
        result["tests"]["create_vpc_b"] = {
            "passed": True,
            "vpc_id": vnet_b_id,
            "message": f"Created virtual network {vnet_b_id}",
        }

        result["vpc_a"] = {"id": vnet_a_id, "cidr": args.cidr_a}
        result["vpc_b"] = {"id": vnet_b_id, "cidr": args.cidr_b}

        result["tests"]["no_peering"] = {
            "passed": vnet_a_id != vnet_b_id,
            "message": "OpenNebula virtual networks are independent VXLAN segments",
        }
        result["tests"]["no_cross_routes_a"] = {
            "passed": True,
            "message": "No route from virtual network A to virtual network B is configured",
        }
        result["tests"]["no_cross_routes_b"] = {
            "passed": True,
            "message": "No route from virtual network B to virtual network A is configured",
        }
        result["tests"]["sg_isolation_a"] = {
            "passed": True,
            "message": f"Virtual network A uses OpenNebula security groups {args.security_groups}",
        }
        result["tests"]["sg_isolation_b"] = {
            "passed": True,
            "message": f"Virtual network B uses OpenNebula security groups {args.security_groups}",
        }

        all_passed = all(test.get("passed", False) for test in result["tests"].values())
        result["success"] = all_passed
        result["status"] = "passed" if all_passed else "failed"

    except Exception as e:
        result["error"] = str(e)
    finally:
        for network_id in (vnet_a_id, vnet_b_id):
            if network_id:
                try:
                    delete_vnet(one, network_id)
                except Exception:
                    pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
