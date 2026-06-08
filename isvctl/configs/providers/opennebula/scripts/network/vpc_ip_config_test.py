#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Inspect OpenNebula VM network-context IP configuration."""

from __future__ import annotations

import argparse
import json
import re
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
    _terminate_vm,
    _vm_nics,
    _wait_for_vm_running,
    ssh_run,
    wait_for_ssh,
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


def _find_nic_by_id(vm_info: Any, nic_id: int) -> Any | None:
    """Return a VM NIC by NIC_ID."""
    for nic in _vm_nics(vm_info):
        if _nic_id(nic) == nic_id:
            return nic
    return None


def _wait_for_nic(one: Any, vm_id: str, nic_id: int, timeout: int, interval: int = 2) -> tuple[Any, Any]:
    """Wait until the requested VM NIC exists and has an IP address."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        nic = _find_nic_by_id(vm_info, nic_id)
        if nic is not None and _nic_ip(nic):
            return vm_info, nic
        time.sleep(interval)

    raise RuntimeError(f"Timed out waiting for VM {vm_id} NIC {nic_id} to receive an IP")


def _ssh_ip(vm_info: Any, ssh_nic_id: int) -> str:
    """Return the VM address used for SSH."""
    ssh_nic = _find_nic_by_id(vm_info, ssh_nic_id)
    ssh_ip = _nic_ip(ssh_nic) if ssh_nic is not None else None
    ssh_ip = ssh_ip or _context_ip(vm_info, ssh_nic_id)
    if not ssh_ip:
        raise RuntimeError(f"VM has no SSH IP on NIC {ssh_nic_id}")
    return ssh_ip


def _parse_resolv_conf(text: str) -> tuple[list[str], list[str]]:
    """Return nameserver and search/domain entries from resolv.conf."""
    nameservers: list[str] = []
    domains: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if match := re.match(r"^nameserver\s+(\S+)", stripped):
            nameservers.append(match.group(1))
        elif match := re.match(r"^(search|domain)\s+(.+)", stripped):
            domains.extend(value for value in match.group(2).split() if value)

    return nameservers, domains


def _subnet_record(network_id: str, nic_id: int, cidr: str, region: str, available_ips: int) -> dict[str, Any]:
    """Build a provider-neutral subnet record for the NAT/context network."""
    return {
        "subnet_id": f"{network_id}:nic-{nic_id}",
        "cidr": cidr,
        "az": region,
        "availability_zone": region,
        "auto_assign_public_ip": False,
        "available_ips": available_ips,
    }


def _cleanup_vm(one: Any, vm_id: str | None, skip_cleanup: bool) -> tuple[bool, list[str]]:
    """Terminate the temporary VM unless cleanup is skipped."""
    if skip_cleanup:
        return False, []
    if not vm_id:
        return True, []

    try:
        _terminate_vm(one, vm_id)
    except Exception as e:
        return True, [f"vm:{vm_id}: {e}"]
    return True, []


def run_vpc_ip_config_test(args: argparse.Namespace, one: Any | None = None) -> dict[str, Any]:
    """Run OpenNebula VPC/IP configuration checks and return the JSON contract result."""
    if not args.key_file:
        raise RuntimeError("--key-file is required for OpenNebula VPC IP configuration checks")

    one = one or get_one_server(args.xmlrpc_url, args.auth)
    suffix = uuid.uuid4().hex[:8]
    vm_id: str | None = None
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "vpc_ip_config",
        "status": "failed",
        "network_id": "",
        "cidr": args.cidr,
        "subnets": [],
        "dhcp_options": None,
        "tests": {},
    }

    try:
        vm_id = _instantiate_template(one, args.template_id, f"{args.name_prefix}-{suffix}")
        result["instance_id"] = vm_id
        result["tests"]["instantiate_vm"] = _passed("Temporary VM instantiated", instance_id=vm_id)

        vm_info = _wait_for_vm_running(one, vm_id, args.vm_wait_timeout)
        vm_info, context_nic = _wait_for_nic(one, vm_id, args.network_nic_id, args.ip_wait_timeout)
        ssh_ip = _ssh_ip(vm_info, args.ssh_nic_id)
        network_id = _nic_network_id(context_nic)
        if not network_id:
            raise RuntimeError(f"VM NIC {args.network_nic_id} has no network identifier")

        result["network_id"] = network_id
        result["subnets"] = [
            _subnet_record(network_id, args.network_nic_id, args.cidr, args.region, args.available_ips),
        ]
        result["tests"]["network_context_nic"] = _passed(
            "Network-context NIC is present",
            nic_id=args.network_nic_id,
            network_id=network_id,
            ip=_nic_ip(context_nic),
        )

        if not wait_for_ssh(ssh_ip, args.ssh_user, args.key_file, args.ssh_wait_timeout):
            raise RuntimeError(f"SSH not ready on VM {vm_id} at {ssh_ip}")

        exit_code, stdout, stderr = ssh_run(
            ssh_ip,
            args.ssh_user,
            args.key_file,
            "cat /etc/resolv.conf",
            timeout=args.ssh_command_timeout,
        )
        if exit_code != 0:
            raise RuntimeError((stderr or stdout or f"cat /etc/resolv.conf exited with {exit_code}").strip())

        nameservers, domains = _parse_resolv_conf(stdout)
        dns_passed = args.expected_dns in nameservers
        search_passed = args.expected_search_domain in domains
        result["tests"]["dns_nameserver_rendered"] = (
            _passed("Expected DNS nameserver rendered in guest", nameservers=nameservers)
            if dns_passed
            else _failed(f"Expected DNS {args.expected_dns} not found in guest resolv.conf", nameservers=nameservers)
        )
        result["tests"]["search_domain_rendered"] = (
            _passed("Expected search domain rendered in guest", domains=domains)
            if search_passed
            else _failed(
                f"Expected search domain {args.expected_search_domain} not found in guest resolv.conf",
                domains=domains,
            )
        )
        result["tests"]["ntp_not_applicable"] = _passed(
            "OpenNebula network context has no NTP equivalent",
            skipped=True,
        )

        result["dhcp_options"] = {
            "dhcp_options_id": f"opennebula-network-context-{network_id}",
            "domain_name": args.expected_search_domain,
            "domain_name_servers": nameservers,
            "ntp_servers": [],
            "ntp_supported": False,
        }

    except Exception as e:
        result["error"] = str(e)
        result["tests"].setdefault("vpc_ip_config_error", _failed(str(e)))
    finally:
        cleaned_up, cleanup_errors = _cleanup_vm(one, vm_id, args.skip_cleanup)
        result["cleanup"] = cleaned_up
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            result["tests"]["cleanup"] = _failed("; ".join(cleanup_errors))

    all_tests_passed = bool(result["tests"]) and all(test.get("passed", False) for test in result["tests"].values())
    result["success"] = all_tests_passed and not result.get("cleanup_errors")
    result["status"] = "passed" if result["success"] else "failed"
    return result


def main() -> int:
    """Run OpenNebula VPC/IP configuration checks and emit structured JSON."""
    parser = argparse.ArgumentParser(description="Test OpenNebula VPC IP configuration")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula VM template ID")
    parser.add_argument("--cidr", required=True, help="CIDR block for the NAT/context network")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument("--ssh-nic-id", type=int, default=0, help="Template NIC_ID used for SSH access")
    parser.add_argument("--network-nic-id", type=int, default=1, help="Template NIC_ID with DNS network context")
    parser.add_argument("--expected-dns", default="1.1.1.1", help="Expected resolver in guest resolv.conf")
    parser.add_argument(
        "--expected-search-domain",
        default="opennebula.io",
        help="Expected search/domain entry in guest resolv.conf",
    )
    parser.add_argument("--available-ips", type=int, default=16, help="Available IP capacity to report")
    parser.add_argument("--name-prefix", default="isv-vpc-ip-config", help="Temporary VM name prefix")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VM to run")
    parser.add_argument("--ip-wait-timeout", type=int, default=120, help="Seconds to wait for VM IP assignment")
    parser.add_argument("--ssh-wait-timeout", type=int, default=300, help="Seconds to wait for SSH access")
    parser.add_argument("--ssh-command-timeout", type=int, default=30, help="Seconds allowed for SSH commands")
    parser.add_argument("--skip-cleanup", action="store_true", help="Keep temporary VM for debugging")
    args = parser.parse_args()

    try:
        result = run_vpc_ip_config_test(args)
    except Exception as e:
        result = {
            "success": False,
            "platform": "network",
            "test_name": "vpc_ip_config",
            "status": "failed",
            "network_id": "",
            "cidr": args.cidr,
            "subnets": [],
            "dhcp_options": None,
            "tests": {"vpc_ip_config_error": _failed(str(e))},
            "error": str(e),
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
