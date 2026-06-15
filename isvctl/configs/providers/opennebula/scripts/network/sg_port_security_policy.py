#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula custom port security policy on a VM NIC."""

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
    delete_security_group,
    get_one_server,
    get_value,
    has_security_group_rule,
    tcp_rule,
)

DEFAULT_SECURITY_GROUP_ID = "0"
POLICY_CIDR = "10.0.0.0/8"
DEFAULT_ALLOWED_PORT = 8443
VM_RUNNING_STATE = 3
VM_RUNNING_LCM_STATE = 3
VM_DONE_STATE = 6
VM_FAILED_STATES = {7, 11}
PORT_SECURITY_TEST_NAMES = [
    "create_virtual_interface",
    "apply_port_policy",
    "allowed_port_permitted",
    "unlisted_port_blocked",
    "other_interface_unaffected",
    "cleanup",
]


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


def _failed_contract(error: str) -> dict[str, dict[str, Any]]:
    """Return a complete failed result contract for early setup failures."""
    return {name: _failed(error) for name in PORT_SECURITY_TEST_NAMES}


def _as_list(value: Any) -> list[Any]:
    """Normalize pyone scalar-or-list values."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _get_field(item: Any, key: str, default: Any = None) -> Any:
    """Read a pyone field, accepting exact or case-insensitive key names."""
    value = get_value(item, key, None)
    if value is not None:
        return value

    candidates = {key.upper(), key.lower()}
    if isinstance(item, dict):
        lowered = {str(item_key).lower(): item_value for item_key, item_value in item.items()}
        for candidate in candidates:
            value = lowered.get(candidate.lower())
            if value is not None:
                return value
        return default

    for candidate in candidates:
        value = getattr(item, candidate, None)
        if value is not None:
            return value

    return default


def _split_sg_ids(value: Any) -> set[str]:
    """Return normalized security group IDs from an OpenNebula value."""
    if value is None:
        return set()
    if isinstance(value, list):
        items = value
    else:
        items = str(value).replace(" ", "").replace("[", "").replace("]", "").replace('"', "").split(",")
    return {str(item).strip() for item in items if str(item).strip()}


def _parse_int(value: str, field_name: str) -> int:
    """Parse an integer CLI value."""
    try:
        return int(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{field_name} must be an integer, got {value!r}") from e


def _instantiate_vm(one: Any, template_id: int, name: str) -> str:
    """Instantiate a VM template and return the VM ID."""
    attempts = (
        (template_id, name, False, "", False),
        (template_id, name, False, ""),
        (template_id, name),
    )
    last_error: TypeError | None = None
    for args in attempts:
        try:
            return str(int(one.template.instantiate(*args)))
        except TypeError as e:
            last_error = e

    raise RuntimeError(f"Could not call template.instantiate: {last_error}")


def _wait_for_vm_running(one: Any, vm_id: str, timeout: int) -> None:
    """Wait until an OpenNebula VM reaches ACTIVE/RUNNING."""
    deadline = time.time() + timeout
    last_state = "unknown"

    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        state = int(_get_field(vm_info, "STATE", -1))
        lcm_state = int(_get_field(vm_info, "LCM_STATE", -1))
        last_state = f"{state}/{lcm_state}"
        if state == VM_RUNNING_STATE and lcm_state == VM_RUNNING_LCM_STATE:
            return
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
            if int(_get_field(vm_info, "STATE", -1)) == VM_DONE_STATE:
                return
        except Exception:
            return
        time.sleep(5)


def _vm_nics(vm_info: Any) -> list[Any]:
    """Return VM NIC records."""
    template = _get_field(vm_info, "TEMPLATE", {})
    return _as_list(_get_field(template, "NIC"))


def _nic_matches_id(nic: Any, nic_id: int) -> bool:
    """Return whether a NIC record has the requested NIC_ID."""
    value = _get_field(nic, "NIC_ID")
    if value is None:
        return nic_id == 0
    try:
        return int(value) == nic_id
    except (TypeError, ValueError):
        return False


def _vm_nic_sg_ids(one: Any, vm_id: str, nic_id: int) -> set[str]:
    """Return security group IDs directly attached to a VM NIC."""
    vm_info = one.vm.info(int(vm_id))
    for nic in _vm_nics(vm_info):
        if _nic_matches_id(nic, nic_id):
            return _split_sg_ids(_get_field(nic, "SECURITY_GROUPS"))
    raise RuntimeError(f"NIC {nic_id} was not found on VM {vm_id}")


def _attach_sg_to_vm_nic(one: Any, vm_id: str, nic_id: int, sg_id: str) -> None:
    """Attach a security group to a VM NIC."""
    try:
        one.vm.attachsg(int(vm_id), nic_id, int(sg_id))
    except AttributeError:
        one.vm.attach_sg(int(vm_id), nic_id, int(sg_id))


def _detach_sg_from_vm_nic(one: Any, vm_id: str, nic_id: int, sg_id: str) -> None:
    """Detach a security group from a VM NIC."""
    try:
        one.vm.detachsg(int(vm_id), nic_id, int(sg_id))
    except AttributeError:
        one.vm.detach_sg(int(vm_id), nic_id, int(sg_id))


def _wait_for_target_nic_policy(
    one: Any,
    vm_id: str,
    nic_id: int,
    sg_id: str,
    timeout: int = 60,
    interval: int = 2,
) -> set[str]:
    """Wait until target NIC has the test SG and no default SG."""
    deadline = time.time() + timeout
    current: set[str] = set()

    while time.time() < deadline:
        current = _vm_nic_sg_ids(one, vm_id, nic_id)
        if str(sg_id) in current and DEFAULT_SECURITY_GROUP_ID not in current:
            return current
        time.sleep(interval)

    return current


def _sg_template(name: str, allowed_port: int) -> str:
    """Build the port-policy security group template."""
    return build_sg_template(
        name,
        "ISV port security policy test",
        [allow_all_egress_rule(), tcp_rule("INBOUND", allowed_port, POLICY_CIDR)],
    )


def _create_port_policy_sg(one: Any, suffix: str, allowed_port: int) -> str:
    """Create the test security group."""
    return allocate_security_group(one, _sg_template(f"isv-port-policy-{suffix}", allowed_port))


def _tcp_port_allowed(one: Any, sg_id: str, port: int) -> bool:
    """Return whether the SG allows the requested inbound TCP port."""
    return has_security_group_rule(
        one.secgroup.info(int(sg_id)),
        protocol="TCP",
        rule_type="INBOUND",
        port=port,
        cidr=POLICY_CIDR,
    )


def _test_port_security_policy(one: Any, args: argparse.Namespace, suffix: str) -> dict[str, Any]:
    """Run the OpenNebula port security policy checks."""
    tests: dict[str, Any] = {}
    sg_id = None
    vm_ids: list[str] = []
    expected_without_cleanup = PORT_SECURITY_TEST_NAMES[:-1]

    try:
        template_id = _parse_int(args.template_id, "--template-id")
        allowed_port = args.allowed_port
        adjacent_port = allowed_port + 1

        sg_id = _create_port_policy_sg(one, suffix, allowed_port)
        target_vm = _instantiate_vm(one, template_id, f"isv-port-policy-target-{suffix}")
        vm_ids.append(target_vm)
        _wait_for_vm_running(one, target_vm, args.vm_wait_timeout)
        other_vm = _instantiate_vm(one, template_id, f"isv-port-policy-other-{suffix}")
        vm_ids.append(other_vm)
        _wait_for_vm_running(one, other_vm, args.vm_wait_timeout)

        target_initial_sgs = sorted(_vm_nic_sg_ids(one, target_vm, args.nic_id))
        other_initial_sgs = sorted(_vm_nic_sg_ids(one, other_vm, args.nic_id))
        tests["create_virtual_interface"] = _passed(
            "Target and unrelated VM NICs are available",
            target_vm_id=target_vm,
            other_vm_id=other_vm,
            nic_id=args.nic_id,
            target_initial_security_groups=target_initial_sgs,
            other_initial_security_groups=other_initial_sgs,
        )

        default_detached = DEFAULT_SECURITY_GROUP_ID in set(target_initial_sgs)
        if default_detached:
            _detach_sg_from_vm_nic(one, target_vm, args.nic_id, DEFAULT_SECURITY_GROUP_ID)
        _attach_sg_to_vm_nic(one, target_vm, args.nic_id, sg_id)
        target_final_sgs = _wait_for_target_nic_policy(one, target_vm, args.nic_id, sg_id)
        if str(sg_id) in target_final_sgs and DEFAULT_SECURITY_GROUP_ID not in target_final_sgs:
            tests["apply_port_policy"] = _passed(
                "Port policy security group replaced default SG on target NIC",
                sg_id=sg_id,
                default_sg_detached=default_detached,
                target_security_groups=sorted(target_final_sgs),
            )
        else:
            tests["apply_port_policy"] = _failed(
                "Target NIC did not converge to the port policy SG without default SG",
                sg_id=sg_id,
                target_security_groups=sorted(target_final_sgs),
            )

        tests["allowed_port_permitted"] = (
            _passed(f"TCP/{allowed_port} is allowed by the port policy SG", sg_id=sg_id, port=allowed_port)
            if _tcp_port_allowed(one, sg_id, allowed_port)
            else _failed(f"TCP/{allowed_port} is not allowed by the port policy SG", sg_id=sg_id, port=allowed_port)
        )
        tests["unlisted_port_blocked"] = (
            _passed(f"TCP/{adjacent_port} is not allowed by the port policy SG", sg_id=sg_id, port=adjacent_port)
            if not _tcp_port_allowed(one, sg_id, adjacent_port)
            else _failed(f"TCP/{adjacent_port} is allowed by the port policy SG", sg_id=sg_id, port=adjacent_port)
        )

        other_final_sgs = _vm_nic_sg_ids(one, other_vm, args.nic_id)
        tests["other_interface_unaffected"] = (
            _passed(
                "Port policy SG is absent from unrelated VM NIC",
                other_vm_id=other_vm,
                nic_id=args.nic_id,
                other_security_groups=sorted(other_final_sgs),
            )
            if str(sg_id) not in other_final_sgs
            else _failed(
                "Port policy SG leaked to unrelated VM NIC",
                other_vm_id=other_vm,
                nic_id=args.nic_id,
                other_security_groups=sorted(other_final_sgs),
            )
        )

    except Exception as e:
        for key in expected_without_cleanup:
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
            _passed("Port security policy resources cleaned up")
            if not cleanup_errors
            else _failed("; ".join(cleanup_errors))
        )

    return tests


def main() -> int:
    """Run OpenNebula port security policy checks and emit JSON."""
    parser = argparse.ArgumentParser(description="Test OpenNebula port security policy on virtual interfaces")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--template-id", required=True, help="OpenNebula VM template ID")
    parser.add_argument("--nic-id", type=int, default=0, help="VM NIC ID for SG policy replacement")
    parser.add_argument("--allowed-port", type=int, default=DEFAULT_ALLOWED_PORT)
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VM probes")
    args = parser.parse_args()

    suffix = uuid.uuid4().hex[:8]
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "sg_port_security_policy",
        "status": "failed",
        "allowed_port": args.allowed_port,
        "policy_cidr": POLICY_CIDR,
        "tests": {},
    }

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        result["tests"] = _test_port_security_policy(one, args, suffix)
        result["success"] = all(test.get("passed", False) for test in result["tests"].values())
        result["status"] = "passed" if result["success"] else "failed"
    except Exception as e:
        result["error"] = str(e)
        result["tests"] = _failed_contract(str(e))

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
