#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Launch OpenNebula bare-metal instance for BMaaS testing.

OpenNebula exposes NICo bare-metal provisioning through the regular VM
lifecycle API. This script instantiates a provider-selected nico template and
emits the provider-neutral bare metal launch contract consumed by isvtest.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
import time
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


def as_list(value: Any) -> list[Any]:
    """Normalize a pyone scalar-or-list value to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def public_key_fingerprint(public_key: str) -> str:
    """Return the OpenSSH SHA256 fingerprint for a single public key line."""
    parts = public_key.strip().split()
    if len(parts) < 2:
        raise ValueError("public key line has no key payload")

    try:
        key_blob = base64.b64decode(parts[1].encode(), validate=True)
    except binascii.Error as e:
        raise ValueError("public key payload is not valid base64") from e

    digest = base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def public_key_fingerprints(public_keys: str) -> list[str]:
    """Return stable SHA256 fingerprints for one or more public keys."""
    fingerprints: list[str] = []
    for line in public_keys.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            fingerprints.append(public_key_fingerprint(candidate))
        except ValueError:
            continue
    return sorted(set(fingerprints))


def get_user_ssh_public_key(one: Any, vm_info: Any) -> str:
    """Return the OpenNebula owner user's registered SSH public key."""
    uid = get_value(vm_info, "UID")
    if uid is None:
        return ""

    try:
        user_info = one.user.info(int(uid))
    except TypeError:
        user_info = one.user.info(int(uid), False, False)
    user_template = get_value(user_info, "TEMPLATE", {})
    return str(get_value(user_template, "SSH_PUBLIC_KEY", "") or "")


def get_context(template: Any) -> dict[str, Any]:
    """Extract an OpenNebula CONTEXT vector as a plain dictionary."""
    context = get_value(template, "CONTEXT", {})
    if isinstance(context, dict):
        return dict(context)
    if hasattr(context, "__dict__"):
        return {key: value for key, value in vars(context).items() if not key.startswith("_")}
    return {}


def get_monitoring(vm_info: Any) -> dict[str, Any]:
    """Extract OpenNebula monitoring data as a plain dictionary."""
    monitoring = get_value(vm_info, "MONITORING", {})
    if isinstance(monitoring, dict):
        return dict(monitoring)
    if hasattr(monitoring, "__dict__"):
        return {key: value for key, value in vars(monitoring).items() if not key.startswith("_")}
    return {}


def get_deploy_id(vm_info: Any) -> str | None:
    """Return the VMM deploy ID, which is the NICo instance ID for nico VMs."""
    deploy_id = get_value(vm_info, "DEPLOY_ID")
    if deploy_id:
        return str(deploy_id)

    history = get_value(get_value(vm_info, "HISTORY_RECORDS", {}), "HISTORY")
    for record in reversed(as_list(history)):
        deploy_id = get_value(record, "VM_MAD_DEPLOY_ID") or get_value(record, "DEPLOY_ID")
        if deploy_id:
            return str(deploy_id)

    return None


def get_ip(vm_info: Any) -> tuple[str | None, str | None]:
    """Return the best VM IP address and associated network identifier."""
    monitoring = get_monitoring(vm_info)
    for key in ("NIC0_IP", "PUBLIC_IP", "IP"):
        if monitoring.get(key):
            return str(monitoring[key]), None

    template = get_value(vm_info, "TEMPLATE", {})
    context = get_context(template)
    for key in ("ETH0_IP", "PUBLIC_IP", "IP"):
        if context.get(key):
            return str(context[key]), None

    for nic in as_list(get_value(template, "NIC")):
        ip = get_value(nic, "IP")
        network_id = get_value(nic, "NETWORK_ID") or get_value(nic, "NETWORK")
        if ip:
            return str(ip), str(network_id) if network_id else None

    return None, None


def map_state(state: int, lcm_state: int) -> str:
    """Map OpenNebula VM states to the provider-neutral instance contract."""
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


def wait_for_deploy_id(one: Any, vm_id: int, timeout: int) -> tuple[Any, str, dict[str, Any]]:
    """Wait for the NICo deploy ID that can arrive after OpenNebula RUNNING."""
    start_time = time.time()
    last_status = ""

    while time.time() - start_time < timeout:
        vm_info = one.vm.info(vm_id)
        monitoring = get_monitoring(vm_info)
        deploy_id = get_deploy_id(vm_info)
        nico_status = str(monitoring.get("NICO_STATUS", ""))

        if nico_status and nico_status != last_status:
            print(f"NICo status: {nico_status}", file=sys.stderr)
            last_status = nico_status

        if deploy_id:
            return vm_info, deploy_id, monitoring

        if nico_status in {"Error", "Failed"}:
            raise RuntimeError(f"NICo instance entered {nico_status} state")

        time.sleep(15)

    raise RuntimeError("Timeout waiting for NICo DEPLOY_ID")


def main() -> int:
    """Launch an OpenNebula bare-metal instance from a template."""
    parser = argparse.ArgumentParser(description="Launch OpenNebula bare-metal instance")
    parser.add_argument("--name", default="isv-bm-test-gpu", help="Instance name")
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula template ID")
    parser.add_argument("--timeout", type=int, default=1200, help="Seconds to wait for RUNNING state")
    parser.add_argument(
        "--metadata-timeout",
        type=int,
        default=3600,
        help="Seconds to wait for NICo DEPLOY_ID after RUNNING state",
    )
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "instance_id": None,
        "instance_type": str(args.template_id),
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        vm_id = one.template.instantiate(args.template_id, args.name)
        result["instance_id"] = str(vm_id)

        start_time = time.time()
        vm_info = None
        while time.time() - start_time < args.timeout:
            vm_info = one.vm.info(vm_id)
            state = int(get_value(vm_info, "STATE", -1))
            lcm_state = int(get_value(vm_info, "LCM_STATE", -1))
            result["state"] = map_state(state, lcm_state)

            if result["state"] == "running":
                break
            if result["state"] in {"failed", "terminated"}:
                raise RuntimeError(f"Instance entered {result['state']} state {state}/{lcm_state}")

            time.sleep(5)
        else:
            raise RuntimeError("Timeout waiting for instance to reach RUNNING state")

        vm_info, deploy_id, monitoring = wait_for_deploy_id(
            one,
            vm_id,
            args.metadata_timeout,
        )
        template = get_value(vm_info, "TEMPLATE", {})
        context = get_context(template)
        user_key = get_user_ssh_public_key(one, vm_info)
        context_key = str(context.get("SSH_PUBLIC_KEY", "") or "")
        requested_key_names = public_key_fingerprints(user_key)
        observed_key_names = public_key_fingerprints(context_key)

        result["nico_instance_id"] = deploy_id
        result["deploy_id"] = deploy_id
        public_ip, network_id = get_ip(vm_info)
        if public_ip:
            result["public_ip"] = public_ip
            result["private_ip"] = public_ip
        if monitoring.get("NICO_STATUS"):
            result["nico_status"] = str(monitoring["NICO_STATUS"])
        if monitoring.get("MACHINE_ID"):
            result["machine_id"] = str(monitoring["MACHINE_ID"])
        if network_id:
            result["network_id"] = network_id
            result["vpc_id"] = network_id

        result["requested_key_name"] = ",".join(requested_key_names)
        result["key_name"] = ",".join(observed_key_names)
        result["contextualization_completed"] = bool(context)
        result["tests"] = {
            "specified_key": {
                "passed": bool(requested_key_names) and requested_key_names == observed_key_names,
                "message": "CONTEXT/SSH_PUBLIC_KEY matches user TEMPLATE/SSH_PUBLIC_KEY"
                if requested_key_names == observed_key_names
                else "CONTEXT/SSH_PUBLIC_KEY does not match user TEMPLATE/SSH_PUBLIC_KEY",
                "probes": ["user_ssh_public_key", "context_ssh_public_key"],
            }
        }

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
