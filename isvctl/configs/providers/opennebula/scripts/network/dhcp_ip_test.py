#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Launch an OpenNebula VM for DHCP/IP management validation."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.network import get_one_server  # noqa: E402
from test_connectivity import (  # noqa: E402
    _context_ip,
    _instantiate_template,
    _nic_id,
    _nic_ip,
    _nic_network_id,
    _vm_nics,
    _wait_for_vm_running,
    ssh_run,
    wait_for_ssh,
)


def _find_nic_by_id(vm_info: Any, nic_id: int) -> Any | None:
    """Return a VM NIC by NIC_ID."""
    for nic in _vm_nics(vm_info):
        if _nic_id(nic) == nic_id:
            return nic
    return None


def _wait_for_nic(one: Any, vm_id: str, nic_id: int, timeout: int, interval: int = 2) -> tuple[Any, Any]:
    """Wait until the requested NIC exists and has an IP address."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        nic = _find_nic_by_id(vm_info, nic_id)
        if nic is not None and _nic_ip(nic):
            return vm_info, nic
        time.sleep(interval)

    raise RuntimeError(f"Timed out waiting for VM {vm_id} NIC {nic_id} to receive an IP")


def _nic_or_context_ip(vm_info: Any, nic_id: int) -> str:
    """Return an IP from the selected NIC or context."""
    nic = _find_nic_by_id(vm_info, nic_id)
    ip = _nic_ip(nic) if nic is not None else None
    ip = ip or _context_ip(vm_info, nic_id)
    if not ip:
        raise RuntimeError(f"VM has no IP on NIC {nic_id}")
    return ip


def _guest_ipv4_addresses(host: str, user: str, key_file: str, timeout: int) -> list[str]:
    """Return global IPv4 addresses observed inside the guest."""
    command = "ip -4 -o addr show scope global | awk '{split($4, a, \"/\"); print a[1]}'"
    exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=timeout)
    if exit_code != 0:
        raise RuntimeError((stderr or stdout or f"guest IP command exited with {exit_code}").strip())
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def run_dhcp_ip_test(args: argparse.Namespace, one: Any | None = None) -> dict[str, Any]:
    """Launch a VM and emit SSH details for DhcpIpManagementCheck."""
    if not args.key_file:
        raise RuntimeError("--key-file is required for OpenNebula DHCP/IP validation")

    one = one or get_one_server(args.xmlrpc_url, args.auth)
    suffix = uuid.uuid4().hex[:8]
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "dhcp_ip",
        "public_ip": None,
        "private_ip": None,
        "key_file": args.key_file,
        "key_name": None,
        "ssh_user": args.ssh_user,
        "instance_id": None,
        "tests": {},
    }

    try:
        vm_id = _instantiate_template(one, args.template_id, f"{args.name_prefix}-{suffix}")
        result["instance_id"] = vm_id
        result["tests"]["instantiate_vm"] = {"passed": True, "instance_id": vm_id}

        _wait_for_vm_running(one, vm_id, args.vm_wait_timeout)
        vm_info, ssh_nic = _wait_for_nic(one, vm_id, args.ssh_nic_id, args.ip_wait_timeout)
        vm_info, private_nic = _wait_for_nic(one, vm_id, args.private_nic_id, args.ip_wait_timeout)

        ssh_target = _nic_or_context_ip(vm_info, args.ssh_nic_id)
        private_ip = _nic_ip(private_nic)
        if not private_ip:
            raise RuntimeError(f"VM NIC {args.private_nic_id} has no IP")

        result["public_ip"] = ssh_target
        result["private_ip"] = private_ip
        result["ssh_nic_id"] = args.ssh_nic_id
        result["private_nic_id"] = args.private_nic_id
        result["ssh_network_id"] = _nic_network_id(ssh_nic)
        result["private_network_id"] = _nic_network_id(private_nic)
        result["tests"]["ssh_nic_ip_assigned"] = {
            "passed": True,
            "nic_id": args.ssh_nic_id,
            "ip": ssh_target,
            "network_id": result["ssh_network_id"],
        }
        result["tests"]["private_nic_ip_assigned"] = {
            "passed": True,
            "nic_id": args.private_nic_id,
            "ip": private_ip,
            "network_id": result["private_network_id"],
        }

        if not wait_for_ssh(ssh_target, args.ssh_user, args.key_file, args.ssh_wait_timeout):
            raise RuntimeError(f"SSH not ready on VM {vm_id} at {ssh_target}")
        result["tests"]["ssh_ready"] = {"passed": True, "host": ssh_target}

        guest_ips = _guest_ipv4_addresses(ssh_target, args.ssh_user, args.key_file, args.ssh_command_timeout)
        result["guest_ipv4_addresses"] = guest_ips
        if private_ip not in guest_ips:
            raise RuntimeError(
                f"OpenNebula NIC {args.private_nic_id} IP {private_ip} not found in guest addresses: {guest_ips}"
            )
        result["tests"]["guest_ip_matches_platform"] = {
            "passed": True,
            "private_ip": private_ip,
            "guest_ipv4_addresses": guest_ips,
        }

        result["success"] = all(test.get("passed", False) for test in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)
        result["tests"].setdefault("dhcp_ip_error", {"passed": False, "error": str(e)})

    return result


def main() -> int:
    """Launch an OpenNebula VM and emit DHCP validation connection details."""
    parser = argparse.ArgumentParser(description="OpenNebula DHCP/IP management launcher")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula VM template ID")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument("--ssh-nic-id", type=int, default=0, help="NIC_ID used as SSH target")
    parser.add_argument("--private-nic-id", type=int, default=1, help="NIC_ID used for DHCP/IP validation")
    parser.add_argument("--name-prefix", default="isv-dhcp-ip", help="Temporary VM name prefix")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VM to run")
    parser.add_argument("--ip-wait-timeout", type=int, default=120, help="Seconds to wait for NIC IP assignment")
    parser.add_argument("--ssh-wait-timeout", type=int, default=300, help="Seconds to wait for SSH access")
    parser.add_argument("--ssh-command-timeout", type=int, default=30, help="Seconds allowed for SSH commands")
    args = parser.parse_args()

    try:
        result = run_dhcp_ip_test(args)
    except Exception as e:
        result = {
            "success": False,
            "platform": "network",
            "test_name": "dhcp_ip",
            "public_ip": None,
            "private_ip": None,
            "key_file": args.key_file,
            "key_name": None,
            "ssh_user": args.ssh_user,
            "instance_id": None,
            "tests": {"dhcp_ip_error": {"passed": False, "error": str(e)}},
            "error": str(e),
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
