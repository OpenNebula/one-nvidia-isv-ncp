#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Create an OpenNebula VXLAN virtual network for network validation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.network import (  # noqa: E402
    create_vnet,
)


def main() -> int:
    """Create the shared OpenNebula network used by network tests."""
    parser = argparse.ArgumentParser(description="Create OpenNebula virtual network")
    parser.add_argument("--name", default="isv-shared-vnet", help="Virtual network name")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--cidr", default="10.0.0.0/16", help="Network CIDR block")
    parser.add_argument("--subnet-count", type=int, default=2, help="Number of OpenNebula address ranges")
    parser.add_argument("--cluster-id", type=int, default=-1)
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--phydev", required=True)
    parser.add_argument("--security-groups", required=True)
    parser.add_argument("--vn-mad", required=True)
    parser.add_argument("--vxlan-mode", required=True)
    parser.add_argument("--ar-ip", default="", help="Optional first IP for the virtual-network address range")
    parser.add_argument("--ar-size", type=int, default=None, help="Optional size for the virtual-network address range")
    parser.add_argument("--guest-mtu", default="", help="Optional VNet GUEST_MTU value")
    parser.add_argument("--ip-link-conf", default="", help="Optional VNet IP_LINK_CONF value")
    parser.add_argument("--filter-ip-spoofing", default="", help="Optional VNet FILTER_IP_SPOOFING value")
    parser.add_argument("--filter-mac-spoofing", default="", help="Optional VNet FILTER_MAC_SPOOFING value")
    parser.add_argument("--bridge-type", default="", help="Optional VNet BRIDGE_TYPE value")
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
            xmlrpc_url=args.xmlrpc_url,
            auth=args.auth,
            name=args.name,
            cidr=args.cidr,
            subnet_count=args.subnet_count,
            cluster_id=args.cluster_id,
            phydev=args.phydev,
            security_groups=args.security_groups,
            vn_mad=args.vn_mad,
            vxlan_mode=args.vxlan_mode,
            zone=args.region,
            ar_ip=args.ar_ip or None,
            ar_size=args.ar_size,
            guest_mtu=args.guest_mtu or None,
            ip_link_conf=args.ip_link_conf or None,
            filter_ip_spoofing=args.filter_ip_spoofing or None,
            filter_mac_spoofing=args.filter_mac_spoofing or None,
            bridge_type=args.bridge_type or None,
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
