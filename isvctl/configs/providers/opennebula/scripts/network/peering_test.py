#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula VPC peering through a Virtual Router appliance."""

from __future__ import annotations

import argparse
import ipaddress
import json
import shlex
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.network import create_vnet, delete_vnet, get_one_server, quote  # noqa: E402
from test_connectivity import (  # noqa: E402
    _as_list,
    _get_field,
    _instantiate_template,
    _nic_network_id,
    _parse_ping_latency,
    _private_nic_template,
    _wait_for_instance_record,
    _wait_for_vm_running,
    ssh_run,
    wait_for_ssh,
)

VM_DONE_STATE = 6

PEERING_TESTS = (
    "create_vpc_a",
    "create_vpc_b",
    "create_peering",
    "accept_peering",
    "add_routes",
    "peering_active",
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


def _gateway_for(cidr: str) -> str:
    """Return the first usable IPv4 address in a CIDR."""
    network = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 CIDRs are supported for OpenNebula peering")
    if network.num_addresses < 4:
        raise ValueError(f"CIDR {cidr} is too small for a gateway and probe VMs")
    return str(network.network_address + 1)


def _required_int(value: Any, option_name: str) -> int:
    """Return an integer CLI option or raise a clear runtime error."""
    try:
        return int(value)
    except (TypeError, ValueError) as e:
        raise RuntimeError(f"{option_name} is required and must be an integer") from e


def _base_result(args: argparse.Namespace) -> dict[str, Any]:
    """Build the base VPC-peering result envelope."""
    gateway_a = args.gateway_a or _gateway_for(args.cidr_a)
    gateway_b = args.gateway_b or _gateway_for(args.cidr_b)
    return {
        "success": False,
        "platform": "network",
        "test_name": "vpc_peering",
        "status": "failed",
        "vpc_a": {"id": "", "cidr": args.cidr_a, "gateway": gateway_a},
        "vpc_b": {"id": "", "cidr": args.cidr_b, "gateway": gateway_b},
        "vrouter": {},
        "instances": [],
        "tests": {name: _failed("not run") for name in PEERING_TESTS},
    }


def _vrouter_nic_template(network_id: str | int, gateway: str) -> str:
    """Return one Virtual Router NIC vector."""
    return "\n".join(
        [
            "NIC = [",
            f"  NETWORK_ID = {quote(network_id)},",
            f"  IP = {quote(gateway)}",
            "]",
        ]
    )


def _vrouter_template(
    name: str,
    network_a_id: str,
    gateway_a: str,
    network_b_id: str,
    gateway_b: str,
) -> str:
    """Build a Virtual Router template linking both validation networks."""
    return "\n".join(
        [
            f"NAME = {quote(name)}",
            'DESCRIPTION = "Created by isvctl OpenNebula peering validation"',
            _vrouter_nic_template(network_a_id, gateway_a),
            _vrouter_nic_template(network_b_id, gateway_b),
        ]
    )


def _allocate_vrouter(one: Any, template: str) -> str:
    """Allocate an OpenNebula Virtual Router and return its ID."""
    return str(int(one.vrouter.allocate(template)))


def _delete_vrouter(one: Any, vrouter_id: str | int) -> None:
    """Delete an OpenNebula Virtual Router, handling pyone signature variants."""
    try:
        one.vrouter.delete(int(vrouter_id), False)
    except TypeError:
        one.vrouter.delete(int(vrouter_id))


def _vrouter_exists(one: Any, vrouter_id: str | int) -> bool:
    """Return whether a Virtual Router still exists."""
    try:
        one.vrouter.info(int(vrouter_id))
    except Exception:
        return False
    return True


def _wait_for_vrouter_deleted(
    one: Any,
    vrouter_id: str | int,
    timeout: int = 120,
    interval: int = 2,
) -> bool:
    """Wait until a Virtual Router no longer exists."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _vrouter_exists(one, vrouter_id):
            return True
        time.sleep(interval)
    return False


def _terminate_vm(one: Any, vm_id: str | int) -> None:
    """Terminate a VM if it is not already gone or DONE."""
    try:
        vm_info = one.vm.info(int(vm_id))
    except Exception:
        return

    if int(_get_field(vm_info, "STATE", -1)) == VM_DONE_STATE:
        return

    one.vm.action("terminate-hard", int(vm_id))


def _wait_for_vm_removed(
    one: Any,
    vm_id: str | int,
    timeout: int = 300,
    interval: int = 5,
) -> bool:
    """Wait until OpenNebula reports a VM as gone or DONE."""
    deadline = time.time() + timeout
    last_state = "unknown"

    while time.time() < deadline:
        try:
            vm_info = one.vm.info(int(vm_id))
            state = int(_get_field(vm_info, "STATE", -1))
            lcm_state = int(_get_field(vm_info, "LCM_STATE", -1))
            last_state = f"{state}/{lcm_state}"
            if state == VM_DONE_STATE:
                return True
        except Exception:
            return True
        time.sleep(interval)

    print(f"  VM {vm_id} not fully removed after cleanup wait; last state {last_state}", file=sys.stderr)
    return False


def _terminate_and_wait_for_vms(one: Any, vm_ids: list[str], description: str) -> list[str]:
    """Terminate VMs and wait until OpenNebula releases them."""
    cleanup_errors = []

    for vm_id in reversed(vm_ids):
        terminate_error = ""
        try:
            _terminate_vm(one, vm_id)
        except Exception as e:
            terminate_error = str(e)

        try:
            if not _wait_for_vm_removed(one, vm_id):
                error = f"{description}:{vm_id}: still exists after terminate"
                if terminate_error:
                    error = f"{error}; terminate error: {terminate_error}"
                cleanup_errors.append(error)
        except Exception as e:
            cleanup_errors.append(f"{description}:{vm_id}: wait failed: {e}")

    return cleanup_errors


def _instantiate_vrouter(one: Any, vrouter_id: str, template_id: int, name: str) -> None:
    """Instantiate one VM from the Virtual Router template."""
    attempts = (
        (int(vrouter_id), 1, template_id, name, False, ""),
        (int(vrouter_id), 1, template_id, name, False),
        (int(vrouter_id), 1, template_id, name),
    )
    last_error: TypeError | None = None
    for method_args in attempts:
        try:
            one.vrouter.instantiate(*method_args)
            return
        except TypeError as e:
            last_error = e

    raise RuntimeError(f"Could not call vrouter.instantiate: {last_error}")


def _extract_ids(value: Any) -> list[str]:
    """Extract OpenNebula ID values from pyone scalar, list, dict, or object shapes."""
    if value is None:
        return []
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [str(value)]
    if isinstance(value, str):
        return [value] if value.isdigit() else []
    if isinstance(value, list):
        ids: list[str] = []
        for item in value:
            ids.extend(_extract_ids(item))
        return ids
    if isinstance(value, dict):
        for key in ("ID", "VM_ID"):
            if key in value:
                return _extract_ids(value[key])
        return []
    for key in ("ID", "VM_ID"):
        item = getattr(value, key, None)
        if item is not None:
            return _extract_ids(item)
    return []


def _vrouter_vm_ids(vrouter_info: Any) -> list[str]:
    """Return VM IDs associated with a Virtual Router."""
    for key in ("VMS", "VM"):
        ids = _extract_ids(_get_field(vrouter_info, key))
        if ids:
            return ids
    return []


def _vrouter_network_ids(vrouter_info: Any) -> set[str]:
    """Return network IDs connected to a Virtual Router template."""
    template = _get_field(vrouter_info, "TEMPLATE", {})
    nics = _as_list(_get_field(template, "NIC"))
    return {network_id for nic in nics if (network_id := _nic_network_id(nic))}


def _wait_for_vrouter(
    one: Any,
    vrouter_id: str,
    expected_network_ids: set[str],
    timeout: int,
    *,
    require_vms: bool,
) -> tuple[Any, list[str]]:
    """Wait until a Virtual Router has the expected NICs and, optionally, VMs."""
    deadline = time.time() + timeout
    last_error: str | None = None

    while time.time() < deadline:
        try:
            vrouter_info = one.vrouter.info(int(vrouter_id))
            network_ids = _vrouter_network_ids(vrouter_info)
            vm_ids = _vrouter_vm_ids(vrouter_info)
            if expected_network_ids.issubset(network_ids) and (vm_ids or not require_vms):
                return vrouter_info, vm_ids
            last_error = f"networks={sorted(network_ids)}, vm_ids={vm_ids}"
        except Exception as e:
            last_error = str(e)
        time.sleep(2)

    raise RuntimeError(f"Timed out waiting for Virtual Router {vrouter_id}: {last_error}")


def _attach_private_nic(one: Any, vm_id: str, vnet_id: str) -> None:
    """Attach one validation subnet NIC to a VM."""
    try:
        one.vm.attachnic(int(vm_id), _private_nic_template(vnet_id))
    except AttributeError:
        one.vm.attach_nic(int(vm_id), _private_nic_template(vnet_id))


def _launch_peer_vm(
    *,
    one: Any,
    template_id: int,
    name: str,
    vnet_id: str,
    role: str,
    ssh_nic_id: int,
    vm_wait_timeout: int,
    ip_wait_timeout: int,
    created_vm_ids: list[str],
) -> dict[str, Any]:
    """Launch one probe VM, attach its subnet NIC, and return its instance record."""
    vm_id = _instantiate_template(one, template_id, name)
    created_vm_ids.append(vm_id)
    _wait_for_vm_running(one, vm_id, vm_wait_timeout)
    _attach_private_nic(one, vm_id, vnet_id)
    _wait_for_vm_running(one, vm_id, vm_wait_timeout)
    record = _wait_for_instance_record(one, vm_id, vnet_id, ssh_nic_id, ip_wait_timeout)
    record["role"] = role
    return record


def _route_command(private_ip: str, peer_cidr: str, gateway: str, target: str) -> str:
    """Build the guest command that sends peer CIDR traffic through the VRouter gateway."""
    return "\n".join(
        [
            "set -eu",
            'ip_cmd="ip"',
            'if [ "$(id -u)" -ne 0 ]; then ip_cmd="sudo ip"; fi',
            f"private_ip={shlex.quote(private_ip)}",
            f"peer_cidr={shlex.quote(peer_cidr)}",
            f"gateway={shlex.quote(gateway)}",
            f"target={shlex.quote(target)}",
            (
                r"""iface=$($ip_cmd -o -4 addr show | awk -v ip="$private_ip" """
                r"""'$4 ~ "^" ip "/" { iface=$2; sub(/:.*/, "", iface); print iface; exit }')"""
            ),
            'test -n "$iface"',
            '$ip_cmd route replace "$peer_cidr" via "$gateway" dev "$iface"',
            '$ip_cmd route get "$target"',
        ]
    )


def _configure_peer_route(
    *,
    host: str,
    user: str,
    key_file: str,
    private_ip: str,
    peer_cidr: str,
    gateway: str,
    target: str,
    ssh_timeout: int,
) -> dict[str, Any]:
    """Configure one VM route to the peer CIDR through the local VRouter gateway."""
    command = _route_command(private_ip, peer_cidr, gateway, target)
    exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=ssh_timeout)
    if exit_code == 0:
        return _passed(
            "Peer route configured",
            gateway=gateway,
            peer_cidr=peer_cidr,
            route_probe=stdout.strip(),
        )
    return _failed(
        "Failed to configure peer route",
        gateway=gateway,
        peer_cidr=peer_cidr,
        details=(stderr or stdout or f"command exited with {exit_code}").strip(),
    )


def _ping_via_ssh(
    *,
    host: str,
    user: str,
    key_file: str,
    target: str,
    count: int,
    ping_timeout: int,
    ssh_timeout: int,
    retry_timeout: int,
    retry_interval: int,
) -> dict[str, Any]:
    """Ping a peered VM private IP over SSH, retrying brief route convergence."""
    command = f"ping -c {count} -W {ping_timeout} {shlex.quote(target)}"
    deadline = time.time() + retry_timeout
    attempt = 0
    last_error = ""

    while True:
        attempt += 1
        exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=ssh_timeout)
        if exit_code == 0:
            return _passed(
                "Cross-subnet ping succeeded",
                status="active",
                target=target,
                latency_ms=_parse_ping_latency(stdout),
                attempts=attempt,
            )

        last_error = (stderr or stdout or f"ping exited with {exit_code}").strip()
        if time.time() >= deadline:
            break
        time.sleep(retry_interval)

    return _failed("Cross-subnet ping failed", target=target, attempts=attempt, details=last_error)


def _cleanup_resources(
    *,
    one: Any | None,
    vm_ids: list[str],
    vrouter_vm_ids: list[str],
    vrouter_id: str | None,
    network_ids: list[str],
    skip_cleanup: bool,
) -> tuple[bool, list[str]]:
    """Clean up temporary OpenNebula peering resources."""
    if skip_cleanup:
        return False, []
    if one is None:
        return True, []

    cleanup_errors = []
    cleanup_errors.extend(_terminate_and_wait_for_vms(one, vm_ids, "vm"))

    if vrouter_id:
        try:
            _delete_vrouter(one, vrouter_id)
            if not _wait_for_vrouter_deleted(one, vrouter_id):
                cleanup_errors.append(f"vrouter:{vrouter_id}: still exists after delete")
        except Exception as e:
            cleanup_errors.append(f"vrouter:{vrouter_id}: {e}")

    cleanup_errors.extend(_terminate_and_wait_for_vms(one, vrouter_vm_ids, "vrouter-vm"))

    for network_id in reversed(network_ids):
        delete_error = _delete_vnet_with_retry(one, network_id)
        if delete_error:
            cleanup_errors.append(delete_error)

    return True, cleanup_errors


def _delete_vnet_with_retry(
    one: Any,
    network_id: str,
    timeout: int = 180,
    interval: int = 5,
) -> str | None:
    """Delete a VNet, retrying while OpenNebula releases VM leases."""
    deadline = time.time() + timeout
    last_error = ""

    while True:
        try:
            delete_vnet(one, network_id)
            return None
        except Exception as e:
            last_error = str(e)
            if time.time() >= deadline:
                return f"vnet:{network_id}: {last_error}"
            time.sleep(interval)


def _create_peer_network(
    args: argparse.Namespace,
    *,
    name: str,
    cidr: str,
    gateway: str,
) -> dict[str, Any]:
    """Create one OpenNebula network used as a peering subnet."""
    return create_vnet(
        xmlrpc_url=args.xmlrpc_url,
        auth=args.auth,
        name=name,
        cidr=cidr,
        subnet_count=1,
        cluster_id=args.cluster_id,
        phydev=args.phydev,
        security_groups=args.security_groups,
        vn_mad=args.vn_mad,
        vxlan_mode=args.vxlan_mode,
        zone=args.region,
        gateway=gateway,
        guest_mtu=args.guest_mtu or None,
        ip_link_conf=args.ip_link_conf or None,
        filter_ip_spoofing=args.filter_ip_spoofing or None,
        filter_mac_spoofing=args.filter_mac_spoofing or None,
        bridge_type=args.bridge_type or None,
    )


def run_peering_test(args: argparse.Namespace, one: Any | None = None) -> dict[str, Any]:
    """Run the OpenNebula VPC-peering probe and return the JSON contract result."""
    if not args.key_file:
        raise RuntimeError("--key-file is required for OpenNebula peering SSH probes")
    vrouter_template_id = _required_int(args.vrouter_template_id, "--vrouter-template-id")

    one = one or get_one_server(args.xmlrpc_url, args.auth)
    suffix = uuid.uuid4().hex[:8]
    result = _base_result(args)
    gateway_a = result["vpc_a"]["gateway"]
    gateway_b = result["vpc_b"]["gateway"]
    network_ids: list[str] = []
    vm_ids: list[str] = []
    vrouter_vm_ids: list[str] = []
    vrouter_id: str | None = None

    try:
        network_a = _create_peer_network(
            args,
            name=f"{args.name_prefix}-a-{suffix}",
            cidr=args.cidr_a,
            gateway=gateway_a,
        )
        network_a_id = str(network_a["network_id"])
        network_ids.append(network_a_id)
        result["vpc_a"]["id"] = network_a_id
        result["tests"]["create_vpc_a"] = _passed(
            "Created peering subnet A",
            vpc_id=network_a_id,
            cidr=args.cidr_a,
            gateway=gateway_a,
        )

        network_b = _create_peer_network(
            args,
            name=f"{args.name_prefix}-b-{suffix}",
            cidr=args.cidr_b,
            gateway=gateway_b,
        )
        network_b_id = str(network_b["network_id"])
        network_ids.append(network_b_id)
        result["vpc_b"]["id"] = network_b_id
        result["tests"]["create_vpc_b"] = _passed(
            "Created peering subnet B",
            vpc_id=network_b_id,
            cidr=args.cidr_b,
            gateway=gateway_b,
        )

        expected_network_ids = {network_a_id, network_b_id}
        vrouter_template = _vrouter_template(
            f"{args.name_prefix}-vr-{suffix}",
            network_a_id,
            gateway_a,
            network_b_id,
            gateway_b,
        )
        vrouter_id = _allocate_vrouter(one, vrouter_template)
        _wait_for_vrouter(one, vrouter_id, expected_network_ids, args.vrouter_wait_timeout, require_vms=False)
        result["vrouter"] = {"id": vrouter_id, "template_id": str(vrouter_template_id), "vm_ids": []}
        result["tests"]["create_peering"] = _passed(
            "Created OpenNebula Virtual Router peering",
            peering_id=vrouter_id,
            network_ids=sorted(expected_network_ids),
        )

        _instantiate_vrouter(one, vrouter_id, vrouter_template_id, f"{args.name_prefix}-vr-vm-{suffix}")
        _vrouter_info, vrouter_vm_ids = _wait_for_vrouter(
            one,
            vrouter_id,
            expected_network_ids,
            args.vrouter_wait_timeout,
            require_vms=True,
        )
        for vrouter_vm_id in vrouter_vm_ids:
            _wait_for_vm_running(one, vrouter_vm_id, args.vm_wait_timeout)
        result["vrouter"]["vm_ids"] = vrouter_vm_ids
        result["tests"]["accept_peering"] = _passed(
            "Instantiated Virtual Router VM",
            vrouter_vm_ids=vrouter_vm_ids,
        )

        source = _launch_peer_vm(
            one=one,
            template_id=args.template_id,
            name=f"{args.name_prefix}-source-{suffix}",
            vnet_id=network_a_id,
            role="source",
            ssh_nic_id=args.ssh_nic_id,
            vm_wait_timeout=args.vm_wait_timeout,
            ip_wait_timeout=args.ip_wait_timeout,
            created_vm_ids=vm_ids,
        )
        target = _launch_peer_vm(
            one=one,
            template_id=args.template_id,
            name=f"{args.name_prefix}-target-{suffix}",
            vnet_id=network_b_id,
            role="target",
            ssh_nic_id=args.ssh_nic_id,
            vm_wait_timeout=args.vm_wait_timeout,
            ip_wait_timeout=args.ip_wait_timeout,
            created_vm_ids=vm_ids,
        )
        result["instances"] = [source, target]

        source_public_ip = source.get("public_ip")
        source_private_ip = source.get("private_ip")
        target_public_ip = target.get("public_ip")
        target_private_ip = target.get("private_ip")
        if not source_public_ip:
            raise RuntimeError(f"Source VM {source['instance_id']} has no SSH/public IP")
        if not source_private_ip:
            raise RuntimeError(f"Source VM {source['instance_id']} has no subnet A private IP")
        if not target_public_ip:
            raise RuntimeError(f"Target VM {target['instance_id']} has no SSH/public IP")
        if not target_private_ip:
            raise RuntimeError(f"Target VM {target['instance_id']} has no subnet B private IP")

        if not wait_for_ssh(source_public_ip, args.ssh_user, args.key_file, args.ssh_wait_timeout):
            raise RuntimeError(f"SSH not ready on source VM {source['instance_id']} at {source_public_ip}")
        if not wait_for_ssh(target_public_ip, args.ssh_user, args.key_file, args.ssh_wait_timeout):
            raise RuntimeError(f"SSH not ready on target VM {target['instance_id']} at {target_public_ip}")

        route_a = _configure_peer_route(
            host=source_public_ip,
            user=args.ssh_user,
            key_file=args.key_file,
            private_ip=source_private_ip,
            peer_cidr=args.cidr_b,
            gateway=gateway_a,
            target=target_private_ip,
            ssh_timeout=args.ssh_command_timeout,
        )
        route_b = _configure_peer_route(
            host=target_public_ip,
            user=args.ssh_user,
            key_file=args.key_file,
            private_ip=target_private_ip,
            peer_cidr=args.cidr_a,
            gateway=gateway_b,
            target=source_private_ip,
            ssh_timeout=args.ssh_command_timeout,
        )
        routes_ok = route_a.get("passed", False) and route_b.get("passed", False)
        routes_message = (
            "Guest peer routes configured through VRouter gateways" if routes_ok else "Guest route setup failed"
        )
        result["tests"]["add_routes"] = {
            "passed": routes_ok,
            "message": routes_message,
            "vpc_a": route_a,
            "vpc_b": route_b,
        }
        if not routes_ok:
            raise RuntimeError(result["tests"]["add_routes"]["message"])

        result["tests"]["peering_active"] = _ping_via_ssh(
            host=source_public_ip,
            user=args.ssh_user,
            key_file=args.key_file,
            target=target_private_ip,
            count=args.ping_count,
            ping_timeout=args.ping_timeout,
            ssh_timeout=args.ssh_command_timeout,
            retry_timeout=args.ping_retry_timeout,
            retry_interval=args.ping_retry_interval,
        )
        result["tests"]["peering_active"]["peering_id"] = vrouter_id

    except Exception as e:
        result["error"] = str(e)
    finally:
        cleaned_up, cleanup_errors = _cleanup_resources(
            one=one,
            vm_ids=vm_ids,
            vrouter_vm_ids=vrouter_vm_ids,
            vrouter_id=vrouter_id,
            network_ids=network_ids,
            skip_cleanup=args.skip_cleanup,
        )
        result["cleanup"] = cleaned_up
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            result["tests"]["cleanup"] = _failed("; ".join(cleanup_errors))

        all_tests_passed = bool(result["tests"]) and all(
            test.get("passed", False) for test in result["tests"].values()
        )
        result["success"] = all_tests_passed and not cleanup_errors
        result["status"] = "passed" if result["success"] else "failed"

    return result


def main() -> int:
    """Run OpenNebula VPC peering probes and emit structured JSON."""
    parser = argparse.ArgumentParser(description="Test OpenNebula VPC peering through a Virtual Router")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--cidr-a", default="172.20.1.0/24", help="CIDR for peering subnet A")
    parser.add_argument("--cidr-b", default="172.20.2.0/24", help="CIDR for peering subnet B")
    parser.add_argument("--gateway-a", default="", help="Gateway IP for subnet A; defaults to first usable IP")
    parser.add_argument("--gateway-b", default="", help="Gateway IP for subnet B; defaults to first usable IP")
    parser.add_argument("--cluster-id", type=int, default=-1)
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula VM template ID")
    parser.add_argument(
        "--vrouter-template-id",
        required=True,
        help="OpenNebula Virtual Router VM template ID",
    )
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--phydev", required=True)
    parser.add_argument("--security-groups", default="", help="Optional VNet-level security groups")
    parser.add_argument("--vn-mad", required=True)
    parser.add_argument("--vxlan-mode", required=True)
    parser.add_argument("--guest-mtu", default="", help="Optional VNet GUEST_MTU value")
    parser.add_argument("--ip-link-conf", default="", help="Optional VNet IP_LINK_CONF value")
    parser.add_argument("--filter-ip-spoofing", default="", help="Optional VNet FILTER_IP_SPOOFING value")
    parser.add_argument("--filter-mac-spoofing", default="", help="Optional VNet FILTER_MAC_SPOOFING value")
    parser.add_argument("--bridge-type", default="", help="Optional VNet BRIDGE_TYPE value")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument("--ssh-nic-id", type=int, default=0, help="Template NIC_ID used for SSH access")
    parser.add_argument("--name-prefix", default="isv-peering", help="Temporary resource name prefix")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VMs to run")
    parser.add_argument("--vrouter-wait-timeout", type=int, default=180, help="Seconds to wait for VRouter readiness")
    parser.add_argument("--ip-wait-timeout", type=int, default=120, help="Seconds to wait for VM IP assignment")
    parser.add_argument("--ssh-wait-timeout", type=int, default=300, help="Seconds to wait for SSH access")
    parser.add_argument("--ssh-command-timeout", type=int, default=30, help="Seconds allowed for each remote command")
    parser.add_argument("--ping-count", type=int, default=3, help="ICMP echo count")
    parser.add_argument("--ping-timeout", type=int, default=2, help="Seconds to wait for each ping reply")
    parser.add_argument("--ping-retry-timeout", type=int, default=60, help="Seconds to retry ping probes")
    parser.add_argument("--ping-retry-interval", type=int, default=5, help="Seconds between ping probe attempts")
    parser.add_argument("--skip-cleanup", action="store_true", help="Keep temporary resources for debugging")
    args = parser.parse_args()

    try:
        result = run_peering_test(args)
    except Exception as e:
        result = {
            "success": False,
            "platform": "network",
            "test_name": "vpc_peering",
            "status": "failed",
            "tests": {name: _failed("not run") for name in PEERING_TESTS},
            "error": str(e),
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
