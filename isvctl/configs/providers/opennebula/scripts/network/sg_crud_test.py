#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula security group CRUD operations."""

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
    create_vnet,
    delete_security_group,
    delete_vnet,
    get_one_server,
    get_template_rules,
    get_value,
    has_security_group_rule,
    tcp_rule,
    update_security_group,
    wait_for_security_group_deleted,
)


def base_rules() -> list[dict[str, str]]:
    """Return the baseline security group rule set."""
    return [allow_all_egress_rule()]


def has_tcp_rule(sg_info: Any, port: str) -> bool:
    """Return whether a security group has an inbound TCP rule for a port."""
    return has_security_group_rule(sg_info, protocol="TCP", rule_type="INBOUND", port=port, cidr="10.0.0.0/8")


def main() -> int:
    """Run OpenNebula security group CRUD lifecycle tests."""
    parser = argparse.ArgumentParser(description="Test OpenNebula security group CRUD operations")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--cidr", default="10.95.0.0/16", help="CIDR for temporary virtual network")
    parser.add_argument("--cluster-id", type=int, default=-1)
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--phydev", required=True)
    parser.add_argument("--security-groups", required=True)
    parser.add_argument("--vn-mad", required=True)
    parser.add_argument("--vxlan-mode", required=True)
    args = parser.parse_args()

    suffix = str(uuid.uuid4())[:8]
    sg_name = f"isv-sg-crud-test-{suffix}"
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "sg_crud",
        "status": "failed",
        "tests": {},
    }
    network_id = None
    sg_id = None
    one = None

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)

        try:
            network = create_vnet(
                xmlrpc_url=args.xmlrpc_url,
                auth=args.auth,
                name=f"isv-sg-crud-vnet-{suffix}",
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
                "message": f"Created temporary virtual network {network_id}",
            }
        except Exception as e:
            result["tests"]["create_vpc"] = {"passed": False, "error": str(e)}
            raise

        try:
            template = build_sg_template(sg_name, "ISV test SG for CRUD lifecycle", base_rules())
            sg_id = allocate_security_group(one, template)
            result["tests"]["create_sg"] = {
                "passed": True,
                "sg_id": sg_id,
                "message": f"Created security group {sg_id}",
            }
        except Exception as e:
            result["tests"]["create_sg"] = {"passed": False, "error": str(e)}
            raise

        try:
            sg_info = one.secgroup.info(int(sg_id))
            name = str(get_value(sg_info, "NAME", sg_name))
            result["tests"]["read_sg"] = {
                "passed": name == sg_name,
                "name": name,
                "description": "ISV test SG for CRUD lifecycle",
                "rule_count": len(get_template_rules(sg_info)),
                "message": f"Security group {sg_id} readable",
            }
            if name != sg_name:
                result["tests"]["read_sg"]["error"] = f"Name mismatch: expected {sg_name}, got {name}"
        except Exception as e:
            result["tests"]["read_sg"] = {"passed": False, "error": str(e)}

        try:
            template = build_sg_template(
                sg_name,
                "ISV test SG for CRUD lifecycle",
                [*base_rules(), tcp_rule("INBOUND", "443", "10.0.0.0/8")],
            )
            update_security_group(one, sg_id, template)
            sg_info = one.secgroup.info(int(sg_id))
            added = has_tcp_rule(sg_info, "443")
            result["tests"]["update_sg_add_rule"] = {
                "passed": added,
                "rule_added": "tcp/443 from 10.0.0.0/8",
                "message": "Inbound HTTPS rule added and verified",
            }
            if not added:
                result["tests"]["update_sg_add_rule"]["error"] = "Rule not found after secgroup.update"
        except Exception as e:
            result["tests"]["update_sg_add_rule"] = {"passed": False, "error": str(e)}

        try:
            template = build_sg_template(
                sg_name,
                "ISV test SG for CRUD lifecycle",
                [*base_rules(), tcp_rule("INBOUND", "8443", "10.0.0.0/8")],
            )
            update_security_group(one, sg_id, template)
            sg_info = one.secgroup.info(int(sg_id))
            has_443 = has_tcp_rule(sg_info, "443")
            has_8443 = has_tcp_rule(sg_info, "8443")
            result["tests"]["update_sg_modify_rule"] = {
                "passed": has_8443 and not has_443,
                "rule_before": "tcp/443",
                "rule_after": "tcp/8443",
                "message": "Rule modified: 443 -> 8443",
            }
            if has_443 or not has_8443:
                result["tests"]["update_sg_modify_rule"]["error"] = (
                    f"Unexpected state: has_443={has_443}, has_8443={has_8443}"
                )
        except Exception as e:
            result["tests"]["update_sg_modify_rule"] = {"passed": False, "error": str(e)}

        try:
            template = build_sg_template(sg_name, "ISV test SG for CRUD lifecycle", base_rules())
            update_security_group(one, sg_id, template)
            sg_info = one.secgroup.info(int(sg_id))
            has_8443 = has_tcp_rule(sg_info, "8443")
            result["tests"]["update_sg_remove_rule"] = {
                "passed": not has_8443,
                "message": "Inbound rules removed, baseline outbound rule remains",
            }
            if has_8443:
                result["tests"]["update_sg_remove_rule"]["error"] = "tcp/8443 rule still present"
        except Exception as e:
            result["tests"]["update_sg_remove_rule"] = {"passed": False, "error": str(e)}

        try:
            delete_security_group(one, sg_id)
            result["tests"]["delete_sg"] = {
                "passed": True,
                "message": f"Security group {sg_id} deleted",
            }
        except Exception as e:
            result["tests"]["delete_sg"] = {"passed": False, "error": str(e)}

        try:
            deleted = wait_for_security_group_deleted(one, sg_id)
            result["tests"]["verify_deleted"] = {
                "passed": deleted,
                "message": f"Security group {sg_id} confirmed deleted" if deleted else "Security group still exists",
            }
            if deleted:
                sg_id = None
        except Exception as e:
            result["tests"]["verify_deleted"] = {"passed": False, "error": str(e)}

        all_passed = all(test.get("passed", False) for test in result["tests"].values())
        result["success"] = all_passed
        result["status"] = "passed" if all_passed else "failed"

    except Exception as e:
        result["error"] = str(e)
    finally:
        if one and sg_id:
            try:
                delete_security_group(one, sg_id)
            except Exception:
                pass
        if one and network_id:
            try:
                delete_vnet(one, network_id)
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
