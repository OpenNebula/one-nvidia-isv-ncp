#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Describe a running OpenNebula VM instance."""

import argparse
import json
import os
import sys
from typing import Any

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


def get_value(item: Any, key: str, default: Any = None) -> Any:
    """Return a value from a dict-like or attribute-based pyone object."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def as_int(value: Any) -> int | None:
    """Convert OpenNebula numeric fields to int when possible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_list(value: Any) -> list[Any]:
    """Normalize a pyone scalar-or-list value to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def map_vm_state(vm_info: Any) -> str:
    """Map OpenNebula VM state codes to the provider-neutral VM state contract."""
    state = as_int(get_value(vm_info, "STATE"))
    lcm_state = as_int(get_value(vm_info, "LCM_STATE"))

    if state == 3 and lcm_state == 3:
        return "running"
    if state in {0, 1, 2, 10} or state == 3:
        return "pending"
    if state in {4, 5, 8, 9}:
        return "stopped"
    if state == 6:
        return "terminated"
    if state in {7, 11}:
        return "failed"
    return "unknown"


def get_context_ip(template: Any) -> str | None:
    """Return an IP address from the VM CONTEXT section, if present."""
    context = get_value(template, "CONTEXT")
    if context is None:
        return None

    for key in ("ETH0_IP", "PUBLIC_IP", "IP"):
        value = get_value(context, key)
        if value:
            return str(value)

    return None


def get_nic_info(template: Any) -> tuple[str | None, str | None]:
    """Return the first NIC IP and network identifier from a VM template."""
    for nic in as_list(get_value(template, "NIC")):
        ip = get_value(nic, "IP")
        network_id = get_value(nic, "NETWORK_ID") or get_value(nic, "NETWORK")

        if ip:
            return str(ip), str(network_id) if network_id else None

    return None, None


def main() -> int:
    """Describe an OpenNebula VM instance and return its current state."""
    parser = argparse.ArgumentParser(description="Describe OpenNebula instance")
    parser.add_argument("--instance-id", type=int, required=True, help="Instance ID")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--public-ip", help="Fallback public IP to pass through")
    parser.add_argument("--ssh-user", default="root", help="SSH username (default: root)")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instance_id": str(args.instance_id),
        "key_file": args.key_file,
        "ssh_user": args.ssh_user,
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        vm_info = one.vm.info(args.instance_id)

        template = get_value(vm_info, "TEMPLATE", {})
        context_ip = get_context_ip(template)
        nic_ip, network_id = get_nic_info(template)
        ip = context_ip or nic_ip or args.public_ip

        result["state"] = map_vm_state(vm_info)
        result["name"] = str(get_value(vm_info, "NAME", "")) or None
        result["public_ip"] = str(ip) if ip else None
        result["private_ip"] = str(nic_ip or ip) if nic_ip or ip else None

        template_id = get_value(vm_info, "TEMPLATE_ID")
        if template_id is not None:
            result["instance_type"] = str(template_id)
        if network_id:
            result["network_id"] = network_id

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
