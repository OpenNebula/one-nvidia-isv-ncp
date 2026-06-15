#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula security group blocking policy configuration."""

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
    get_rules_by_type,
    has_security_group_rule,
    tcp_rule,
)


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


def _create_security_group(one: Any, name: str, description: str, rules: list[dict[str, str]]) -> str:
    """Create a security group and return its identifier."""
    return allocate_security_group(one, build_sg_template(name, description, rules))


def test_sg_default_deny_inbound(one: Any, suffix: str) -> dict[str, Any]:
    """Verify an SG with no inbound rules exposes no inbound allow rules."""
    sg_id = None
    try:
        sg_id = _create_security_group(
            one,
            f"isv-empty-sg-{suffix}",
            "ISV empty inbound security group",
            [allow_all_egress_rule()],
        )
        sg_info = one.secgroup.info(int(sg_id))
        inbound_rules = get_rules_by_type(sg_info, "INBOUND")
        if not inbound_rules:
            return _passed("Security group has no inbound allow rules", sg_id=sg_id, inbound_rule_count=0)
        return _failed("Expected no inbound rules", sg_id=sg_id, inbound_rule_count=len(inbound_rules))
    except Exception as e:
        return _failed(str(e), sg_id=sg_id)


def test_sg_allows_specific_ssh(one: Any, suffix: str) -> dict[str, Any]:
    """Verify an SG can allow SSH from a specific CIDR."""
    sg_id = None
    allowed_cidr = "192.168.1.0/24"
    try:
        sg_id = _create_security_group(
            one,
            f"isv-ssh-sg-{suffix}",
            "ISV specific SSH security group",
            [allow_all_egress_rule(), tcp_rule("INBOUND", 22, allowed_cidr)],
        )
        sg_info = one.secgroup.info(int(sg_id))
        rule_found = has_security_group_rule(
            sg_info,
            protocol="TCP",
            rule_type="INBOUND",
            port=22,
            cidr=allowed_cidr,
        )
        if rule_found:
            return _passed(f"Security group allows SSH from {allowed_cidr}", sg_id=sg_id, allowed_cidr=allowed_cidr)
        return _failed("SSH allow rule not found", sg_id=sg_id, allowed_cidr=allowed_cidr)
    except Exception as e:
        return _failed(str(e), sg_id=sg_id, allowed_cidr=allowed_cidr)


def test_sg_denies_vpc_icmp(one: Any, suffix: str, vpc_cidr: str) -> dict[str, Any]:
    """Verify an SG without ICMP inbound rules does not allow VPC ICMP."""
    sg_id = None
    try:
        sg_id = _create_security_group(
            one,
            f"isv-no-icmp-sg-{suffix}",
            "ISV no ICMP security group",
            [allow_all_egress_rule()],
        )
        sg_info = one.secgroup.info(int(sg_id))
        icmp_allowed = has_security_group_rule(sg_info, protocol="ICMP", rule_type="INBOUND")
        all_inbound_allowed = has_security_group_rule(sg_info, protocol="ALL", rule_type="INBOUND")
        if not icmp_allowed and not all_inbound_allowed:
            return _passed("Security group has no ICMP inbound allow rule", sg_id=sg_id, cidr=vpc_cidr)
        return _failed("ICMP is allowed by security group rules", sg_id=sg_id, cidr=vpc_cidr)
    except Exception as e:
        return _failed(str(e), sg_id=sg_id, cidr=vpc_cidr)


def test_nacl_explicit_deny(one: Any, suffix: str) -> dict[str, Any]:
    """Verify OpenNebula's SG allow-list model denies traffic without a matching allow rule."""
    sg_id = None
    blocked_cidr = "10.0.0.0/8"
    try:
        sg_id = _create_security_group(
            one,
            f"isv-deny-equivalent-sg-{suffix}",
            "ISV deny-equivalent security group",
            [allow_all_egress_rule()],
        )
        sg_info = one.secgroup.info(int(sg_id))
        icmp_allowed = has_security_group_rule(
            sg_info,
            protocol="ICMP",
            rule_type="INBOUND",
            cidr=blocked_cidr,
        )
        all_inbound_allowed = has_security_group_rule(sg_info, protocol="ALL", rule_type="INBOUND")
        if not icmp_allowed and not all_inbound_allowed:
            return _passed(
                "OpenNebula SG allow-list denies ICMP without a matching allow rule",
                policy_id=f"opennebula-sg:{sg_id}",
                blocked_cidr=blocked_cidr,
            )
        return _failed("Expected ICMP to be denied by SG allow-list policy", policy_id=f"opennebula-sg:{sg_id}")
    except Exception as e:
        return _failed(str(e), policy_id=f"opennebula-sg:{sg_id}" if sg_id else "")


def test_sg_restricted_egress(one: Any, suffix: str) -> dict[str, Any]:
    """Verify an SG can restrict outbound traffic to HTTPS."""
    sg_id = None
    try:
        sg_id = _create_security_group(
            one,
            f"isv-egress-sg-{suffix}",
            "ISV HTTPS-only egress security group",
            [tcp_rule("OUTBOUND", 443)],
        )
        sg_info = one.secgroup.info(int(sg_id))
        egress_rules = get_rules_by_type(sg_info, "OUTBOUND")
        https_only = len(egress_rules) == 1 and has_security_group_rule(
            sg_info,
            protocol="TCP",
            rule_type="OUTBOUND",
            port=443,
        )
        if https_only:
            return _passed("Security group egress allows only HTTPS", sg_id=sg_id, egress_rule_count=1)
        return _failed("Unexpected egress rule set", sg_id=sg_id, egress_rule_count=len(egress_rules))
    except Exception as e:
        return _failed(str(e), sg_id=sg_id)


def main() -> int:
    """Run OpenNebula security blocking policy checks."""
    parser = argparse.ArgumentParser(description="Test OpenNebula security blocking rules")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--cidr", default="10.94.0.0/16", help="CIDR for temporary virtual network")
    parser.add_argument("--cluster-id", type=int, default=-1)
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--phydev", required=True)
    parser.add_argument("--security-groups", required=True)
    parser.add_argument("--vn-mad", required=True)
    parser.add_argument("--vxlan-mode", required=True)
    args = parser.parse_args()

    suffix = uuid.uuid4().hex[:8]
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "security_blocking",
        "status": "failed",
        "tests": {},
    }
    one = None
    network_id = None
    sg_ids: list[str] = []

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        network = create_vnet(
            xmlrpc_url=args.xmlrpc_url,
            auth=args.auth,
            name=f"isv-security-vnet-{suffix}",
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
        result["tests"]["create_vpc"] = _passed("Temporary virtual network created", vpc_id=network_id)

        test_result = test_sg_default_deny_inbound(one, suffix)
        result["tests"]["sg_default_deny_inbound"] = test_result
        if test_result.get("sg_id"):
            sg_ids.append(test_result["sg_id"])

        test_result = test_sg_allows_specific_ssh(one, suffix)
        result["tests"]["sg_allows_specific_ssh"] = test_result
        if test_result.get("sg_id"):
            sg_ids.append(test_result["sg_id"])

        test_result = test_sg_denies_vpc_icmp(one, suffix, args.cidr)
        result["tests"]["sg_denies_vpc_icmp"] = test_result
        if test_result.get("sg_id"):
            sg_ids.append(test_result["sg_id"])

        test_result = test_nacl_explicit_deny(one, suffix)
        result["tests"]["nacl_explicit_deny"] = test_result
        policy_id = str(test_result.get("policy_id", ""))
        if policy_id.startswith("opennebula-sg:"):
            sg_ids.append(policy_id.split(":", 1)[1])

        test_result = test_sg_restricted_egress(one, suffix)
        result["tests"]["sg_restricted_egress"] = test_result
        if test_result.get("sg_id"):
            sg_ids.append(test_result["sg_id"])

        all_passed = all(test.get("passed", False) for test in result["tests"].values())
        result["success"] = all_passed
        result["status"] = "passed" if all_passed else "failed"

    except Exception as e:
        result["error"] = str(e)
    finally:
        cleanup_errors = []
        if one:
            for sg_id in reversed(sg_ids):
                try:
                    delete_security_group(one, sg_id)
                except Exception as e:
                    cleanup_errors.append(f"sg:{sg_id}: {e}")
            if network_id:
                try:
                    delete_vnet(one, network_id)
                except Exception as e:
                    cleanup_errors.append(f"vnet:{network_id}: {e}")
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
