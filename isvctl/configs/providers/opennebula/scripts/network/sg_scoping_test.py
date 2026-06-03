#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula security group scoping at node or subnet level."""

from __future__ import annotations

import argparse
import json
import sys
import time
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
    get_value,
    quote,
    tcp_rule,
)

DEFAULT_CIDR = "10.85.0.0/16"
POLICY_CIDR = "10.0.0.0/8"
POLICY_PORT = 443
VM_RUNNING_STATE = 3
VM_RUNNING_LCM_STATE = 3
VM_DONE_STATE = 6
VM_FAILED_STATES = {7, 11}


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


def _as_list(value: Any) -> list[Any]:
    """Normalize pyone scalar-or-list values."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _parse_int(value: str, field_name: str) -> int:
    """Parse an integer CLI value."""
    try:
        return int(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{field_name} must be an integer, got {value!r}") from e


def _split_sg_ids(value: Any) -> set[str]:
    """Return normalized security group IDs from an OpenNebula value."""
    if value is None:
        return set()
    if isinstance(value, list):
        items = value
    else:
        items = str(value).replace(" ", "").split(",")
    return {str(item).strip() for item in items if str(item).strip()}


def _sg_rule_template(name: str, description: str) -> str:
    """Return a standard test security group template."""
    rules = [allow_all_egress_rule(), tcp_rule("INBOUND", POLICY_PORT, POLICY_CIDR)]
    return build_sg_template(name, description, rules)


def _create_test_sg(one: Any, scope: str, suffix: str) -> str:
    """Create the SG used by a scoping test."""
    return allocate_security_group(
        one,
        _sg_rule_template(
            f"isv-sg-scope-{scope}-{suffix}",
            f"ISV SG scoping test ({scope})",
        ),
    )


def _instantiate_vm(one: Any, template_id: int, name: str, timeout: int) -> str:
    """Instantiate a VM from a template and wait until it is running."""
    vm_id = str(int(one.template.instantiate(template_id, name)))
    deadline = time.time() + timeout
    last_state = "unknown"

    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        state = int(get_value(vm_info, "STATE", -1))
        lcm_state = int(get_value(vm_info, "LCM_STATE", -1))
        last_state = f"{state}/{lcm_state}"
        if state == VM_RUNNING_STATE and lcm_state == VM_RUNNING_LCM_STATE:
            return vm_id
        if state in VM_FAILED_STATES:
            raise RuntimeError(f"VM {vm_id} entered failed state {last_state}")
        time.sleep(5)

    raise TimeoutError(f"Timed out waiting for VM {vm_id} to run; last state {last_state}")


def _terminate_vm(one: Any, vm_id: str, timeout: int = 180) -> None:
    """Terminate a VM and wait until OpenNebula reports it done."""
    one.vm.action("terminate-hard", int(vm_id))

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            vm_info = one.vm.info(int(vm_id))
            if int(get_value(vm_info, "STATE", -1)) == VM_DONE_STATE:
                return
        except Exception:
            return
        time.sleep(5)


def _attach_sg_to_vm_nic(one: Any, vm_id: str, nic_id: int, sg_id: str) -> None:
    """Attach a security group to a VM NIC."""
    try:
        one.vm.attachsg(int(vm_id), nic_id, int(sg_id))
    except AttributeError:
        one.vm.attach_sg(int(vm_id), nic_id, int(sg_id))


def _vm_nics(vm_info: Any) -> list[Any]:
    """Return VM NIC records."""
    template = get_value(vm_info, "TEMPLATE", {})
    return _as_list(get_value(template, "NIC"))


def _nic_matches_id(nic: Any, nic_id: int) -> bool:
    """Return whether a NIC record has the requested NIC_ID."""
    value = get_value(nic, "NIC_ID")
    if value is None:
        return nic_id == 0
    try:
        return int(value) == nic_id
    except (TypeError, ValueError):
        return False


def _vm_nic_has_sg(one: Any, vm_id: str, nic_id: int, sg_id: str) -> bool:
    """Return whether a VM NIC has a security group ID attached."""
    vm_info = one.vm.info(int(vm_id))
    for nic in _vm_nics(vm_info):
        if _nic_matches_id(nic, nic_id):
            return str(sg_id) in _split_sg_ids(get_value(nic, "SECURITY_GROUPS"))
    return False


def _wait_for_vm_nic_sg(
    one: Any,
    vm_id: str,
    nic_id: int,
    sg_id: str,
    expected_present: bool,
    timeout: int = 60,
    interval: int = 2,
) -> bool:
    """Wait until a VM NIC security group attachment reaches the expected state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _vm_nic_has_sg(one, vm_id, nic_id, sg_id) is expected_present:
            return True
        time.sleep(interval)
    return False


def _vnet_ars(vnet_info: Any) -> list[Any]:
    """Return virtual-network address range records."""
    ar_pool = get_value(vnet_info, "AR_POOL", {})
    return _as_list(get_value(ar_pool, "AR"))


def _ar_id(ar: Any) -> str:
    """Return an AR identifier."""
    return str(get_value(ar, "AR_ID", ""))


def _ar_has_sg(vnet_info: Any, ar_id: str, sg_id: str) -> bool:
    """Return whether an address range has a security group."""
    for ar in _vnet_ars(vnet_info):
        if _ar_id(ar) == str(ar_id):
            return str(sg_id) in _split_sg_ids(get_value(ar, "SECURITY_GROUPS"))
    return False


def _update_ar_security_groups(one: Any, network_id: str, ar_id: str, sg_id: str) -> None:
    """Set security groups on a virtual-network address range."""
    template = "\n".join(
        [
            "AR = [",
            f"  AR_ID = {quote(ar_id)},",
            f"  SECURITY_GROUPS = {quote(sg_id)}",
            "]",
        ]
    )
    try:
        one.vn.update_ar(int(network_id), template)
    except AttributeError:
        one.vn.updatear(int(network_id), template)


def _test_node_scoping(one: Any, args: argparse.Namespace, suffix: str) -> dict[str, Any]:
    """Run VM/NIC-level SG scoping checks."""
    tests: dict[str, Any] = {}
    sg_id = None
    vm_ids: list[str] = []

    try:
        template_id = _parse_int(args.template_id, "--template-id")
        sg_id = _create_test_sg(one, "node", suffix)
        tests["create_sg"] = _passed("Security group created", sg_id=sg_id)

        target_vm = _instantiate_vm(one, template_id, f"isv-sg-node-target-{suffix}", args.vm_wait_timeout)
        vm_ids.append(target_vm)
        other_vm = _instantiate_vm(one, template_id, f"isv-sg-node-other-{suffix}", args.vm_wait_timeout)
        vm_ids.append(other_vm)

        _attach_sg_to_vm_nic(one, target_vm, args.nic_id, sg_id)
        tests["apply_node_rule"] = _passed(
            "Security group attached to target VM NIC",
            sg_id=sg_id,
            target_vm_id=target_vm,
            other_vm_id=other_vm,
            nic_id=args.nic_id,
        )

        target_has_sg = _wait_for_vm_nic_sg(one, target_vm, args.nic_id, sg_id, True)
        tests["target_node_allowed"] = (
            _passed("Target VM NIC has scoped security group", vm_id=target_vm, nic_id=args.nic_id)
            if target_has_sg
            else _failed("Security group was not found on target VM NIC", vm_id=target_vm, nic_id=args.nic_id)
        )

        other_has_sg = _vm_nic_has_sg(one, other_vm, args.nic_id, sg_id)
        tests["other_node_blocked"] = (
            _passed("Security group is absent from unrelated VM NIC", vm_id=other_vm, nic_id=args.nic_id)
            if not other_has_sg
            else _failed("Security group leaked to unrelated VM NIC", vm_id=other_vm, nic_id=args.nic_id)
        )

    except Exception as e:
        for key in ("create_sg", "apply_node_rule", "target_node_allowed", "other_node_blocked"):
            tests.setdefault(key, _failed(str(e)))
    finally:
        cleanup_errors = []
        for vm_id in reversed(vm_ids):
            try:
                _terminate_vm(one, vm_id)
            except Exception as e:
                cleanup_errors.append(f"vm:{vm_id}: {e}")
        if sg_id:
            try:
                delete_security_group(one, sg_id)
            except Exception as e:
                cleanup_errors.append(f"sg:{sg_id}: {e}")
        tests["cleanup"] = (
            _passed("Node scoping resources cleaned up")
            if not cleanup_errors
            else _failed("; ".join(cleanup_errors))
        )

    return tests


def _test_subnet_scoping(one: Any, args: argparse.Namespace, suffix: str) -> dict[str, Any]:
    """Run AR/subnet-level SG scoping checks."""
    tests: dict[str, Any] = {}
    sg_id = None
    network_id = None

    try:
        sg_id = _create_test_sg(one, "subnet", suffix)
        tests["create_sg"] = _passed("Security group created", sg_id=sg_id)

        network = create_vnet(
            xmlrpc_url=args.xmlrpc_url,
            auth=args.auth,
            name=f"isv-sg-subnet-vnet-{suffix}",
            cidr=args.cidr,
            subnet_count=2,
            cluster_id=args.cluster_id,
            phydev=args.phydev,
            security_groups=args.security_groups,
            vn_mad=args.vn_mad,
            vxlan_mode=args.vxlan_mode,
            zone=args.region,
        )
        network_id = network["network_id"]

        vnet_info = one.vn.info(int(network_id))
        ar_ids = [_ar_id(ar) for ar in _vnet_ars(vnet_info)]
        if len(ar_ids) < 2:
            raise RuntimeError(f"Expected at least 2 address ranges, found {len(ar_ids)}")

        target_ar_id, other_ar_id = ar_ids[0], ar_ids[1]
        _update_ar_security_groups(one, network_id, target_ar_id, sg_id)
        tests["apply_subnet_rule"] = _passed(
            "Security group applied to target address range",
            network_id=network_id,
            target_ar_id=target_ar_id,
            other_ar_id=other_ar_id,
            sg_id=sg_id,
        )

        vnet_info = one.vn.info(int(network_id))
        tests["subnet_allowed"] = (
            _passed("Target address range has scoped security group", ar_id=target_ar_id)
            if _ar_has_sg(vnet_info, target_ar_id, sg_id)
            else _failed("Security group not found on target address range", ar_id=target_ar_id)
        )
        tests["other_subnet_blocked"] = (
            _passed("Security group is absent from unrelated address range", ar_id=other_ar_id)
            if not _ar_has_sg(vnet_info, other_ar_id, sg_id)
            else _failed("Security group leaked to unrelated address range", ar_id=other_ar_id)
        )

    except Exception as e:
        for key in ("create_sg", "apply_subnet_rule", "subnet_allowed", "other_subnet_blocked"):
            tests.setdefault(key, _failed(str(e)))
    finally:
        cleanup_errors = []
        if network_id:
            try:
                delete_vnet(one, network_id)
            except Exception as e:
                cleanup_errors.append(f"vnet:{network_id}: {e}")
        if sg_id:
            try:
                delete_security_group(one, sg_id)
            except Exception as e:
                cleanup_errors.append(f"sg:{sg_id}: {e}")
        tests["cleanup"] = (
            _passed("Subnet scoping resources cleaned up")
            if not cleanup_errors
            else _failed("; ".join(cleanup_errors))
        )

    return tests


def _failed_contract(scope: str, error: str) -> dict[str, dict[str, Any]]:
    """Return all required subtests as failed for an early error."""
    if scope == "node":
        keys = ["create_sg", "apply_node_rule", "target_node_allowed", "other_node_blocked", "cleanup"]
    else:
        keys = ["create_sg", "apply_subnet_rule", "subnet_allowed", "other_subnet_blocked", "cleanup"]
    return {key: _failed(error) for key in keys}


def main() -> int:
    """Run an OpenNebula security group scoping test."""
    parser = argparse.ArgumentParser(description="Test OpenNebula SG scoping levels")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--scope", required=True, choices=["node", "subnet"])
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--template-id", default="", help="Template ID for node-scope VM probes")
    parser.add_argument("--nic-id", type=int, default=0, help="VM NIC ID for node-scope SG attachment")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VM probes")
    parser.add_argument("--cidr", default=DEFAULT_CIDR, help="CIDR for subnet-scope virtual network")
    parser.add_argument("--cluster-id", type=int, default=-1)
    parser.add_argument("--phydev", default="")
    parser.add_argument("--security-groups", default="")
    parser.add_argument("--vn-mad", default="")
    parser.add_argument("--vxlan-mode", default="")
    args = parser.parse_args()

    suffix = uuid.uuid4().hex[:8]
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": f"sg_{args.scope}_scoping",
        "scope": args.scope,
        "status": "failed",
        "tests": {},
    }

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        if args.scope == "node":
            result["tests"] = _test_node_scoping(one, args, suffix)
        else:
            result["tests"] = _test_subnet_scoping(one, args, suffix)
        result["success"] = all(test.get("passed", False) for test in result["tests"].values())
        result["status"] = "passed" if result["success"] else "failed"
    except Exception as e:
        result["error"] = str(e)
        result["tests"] = _failed_contract(args.scope, str(e))

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
