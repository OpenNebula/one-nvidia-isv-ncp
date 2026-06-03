#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Create an OpenNebula VXLAN virtual network for network validation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.network import (  # noqa: E402
    DEFAULT_PHYDEV,
    DEFAULT_SECURITY_GROUPS,
    DEFAULT_VN_MAD,
    DEFAULT_VXLAN_MODE,
    create_vnet,
)


def main() -> int:
    """Create the shared OpenNebula network used by network tests."""
    parser = argparse.ArgumentParser(description="Create OpenNebula virtual network")
    parser.add_argument("--name", default="isv-shared-vnet", help="Virtual network name")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"), help="Logical region label")
    parser.add_argument("--cidr", default="10.0.0.0/16", help="Network CIDR block")
    parser.add_argument("--subnet-count", type=int, default=2, help="Number of OpenNebula address ranges")
    parser.add_argument("--cluster-id", type=int, default=int(os.environ.get("ONE_CLUSTER_ID", "-1")))
    parser.add_argument("--phydev", default=os.environ.get("ONE_VNET_PHYDEV", DEFAULT_PHYDEV))
    parser.add_argument(
        "--security-groups",
        default=os.environ.get("ONE_VNET_SECURITY_GROUPS", DEFAULT_SECURITY_GROUPS),
    )
    parser.add_argument("--vn-mad", default=os.environ.get("ONE_VNET_MAD", DEFAULT_VN_MAD))
    parser.add_argument("--vxlan-mode", default=os.environ.get("ONE_VNET_VXLAN_MODE", DEFAULT_VXLAN_MODE))
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "name": args.name,
        "region": args.region,
        "cidr": args.cidr,
        "subnets": [],
    }

    try:
        network = create_vnet(
            name=args.name,
            cidr=args.cidr,
            subnet_count=args.subnet_count,
            cluster_id=args.cluster_id,
            phydev=args.phydev,
            security_groups=args.security_groups,
            vn_mad=args.vn_mad,
            vxlan_mode=args.vxlan_mode,
            zone=args.region,
        )
        result.update(network)
        result["dhcp_options"] = {
            "dhcp_options_id": "opennebula-context",
            "domain_name": "opennebula.local",
            "domain_name_servers": [],
            "ntp_servers": [],
        }
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
