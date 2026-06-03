#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula virtual-network CRUD operations."""

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
    get_value,
    wait_for_vnet_deleted,
    wait_for_vnet,
)


def update_vnet_template(one: Any, network_id: str, template: str) -> None:
    """Append metadata to an OpenNebula virtual-network template."""
    one.vn.update(int(network_id), template, 1)


def main() -> int:
    """Run create/read/update/delete checks for an OpenNebula virtual network."""
    parser = argparse.ArgumentParser(description="Test OpenNebula virtual-network CRUD operations")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"), help="Logical region label")
    parser.add_argument("--cidr", default="10.99.0.0/16", help="Network CIDR block")
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
    vnet_name = f"isv-crud-test-{suffix}"
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "status": "failed",
        "tests": {},
        "vpc_name": vnet_name,
    }
    network_id = None

    try:
        one = get_one_server()

        try:
            network = create_vnet(
                name=vnet_name,
                cidr=args.cidr,
                subnet_count=1,
                cluster_id=args.cluster_id,
                phydev=args.phydev,
                security_groups=args.security_groups,
                vn_mad=args.vn_mad,
                vxlan_mode=args.vxlan_mode,
                zone=args.region,
            )
            network_id = network["network_id"]
            result["network_id"] = network_id
            result["tests"]["create_vpc"] = {
                "passed": True,
                "vpc_id": network_id,
                "cidr": args.cidr,
                "message": f"Created virtual network {network_id}",
            }
        except Exception as e:
            result["tests"]["create_vpc"] = {"passed": False, "error": str(e)}
            raise

        try:
            info = wait_for_vnet(one, network_id)
            result["tests"]["read_vpc"] = {
                "passed": True,
                "state": "available",
                "name": str(get_value(info, "NAME", vnet_name)),
                "message": f"Virtual network {network_id} is available",
            }
        except Exception as e:
            result["tests"]["read_vpc"] = {"passed": False, "error": str(e)}

        try:
            update_vnet_template(one, network_id, 'UPDATE_TEST = "success"\nCREATED_BY = "isvtest"')
            result["tests"]["update_tags"] = {
                "passed": True,
                "tags_added": ["UPDATE_TEST", "CREATED_BY"],
                "message": "Template metadata updated successfully",
            }
        except Exception as e:
            result["tests"]["update_tags"] = {"passed": False, "error": str(e)}

        try:
            update_vnet_template(one, network_id, 'DNS = "opennebula.local"\nNETWORK_CONTEXT = "enabled"')
            result["tests"]["update_dns"] = {
                "passed": True,
                "dns_support": True,
                "dns_hostnames": False,
                "message": "Network context metadata updated successfully",
            }
        except Exception as e:
            result["tests"]["update_dns"] = {"passed": False, "error": str(e)}

        try:
            delete_vnet(one, network_id)
            deleted = wait_for_vnet_deleted(one, network_id)
            message = (
                f"Virtual network {network_id} deleted successfully"
                if deleted
                else "Virtual network still exists"
            )
            result["tests"]["delete_vpc"] = {
                "passed": deleted,
                "message": message,
            }
            if deleted:
                network_id = None
        except Exception as e:
            result["tests"]["delete_vpc"] = {"passed": False, "error": str(e)}

        all_passed = all(test.get("passed", False) for test in result["tests"].values())
        result["success"] = all_passed
        result["status"] = "passed" if all_passed else "failed"

    except Exception as e:
        result["error"] = str(e)
    finally:
        if network_id:
            try:
                delete_vnet(get_one_server(), network_id)
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
