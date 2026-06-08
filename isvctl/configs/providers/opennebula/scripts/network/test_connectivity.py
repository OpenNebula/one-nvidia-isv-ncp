#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula VM connectivity on the shared validation virtual network."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.network import get_one_server, get_value, quote  # noqa: E402

VM_RUNNING_STATE = 3
VM_RUNNING_LCM_STATE = 3
VM_DONE_STATE = 6
VM_FAILED_STATES = {7, 11}
PING_TARGET_INTERNET = "8.8.8.8"


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

    if isinstance(item, dict):
        lowered = {str(item_key).lower(): item_value for item_key, item_value in item.items()}
        return lowered.get(key.lower(), default)

    for candidate in (key.upper(), key.lower()):
        value = getattr(item, candidate, None)
        if value is not None:
            return value

    return default


def _private_nic_template(vnet_id: str | int) -> str:
    """Return a NIC template for the validation virtual network."""
    return "\n".join(
        [
            "NIC = [",
            f"  NETWORK_ID = {quote(vnet_id)}",
            "]",
        ]
    )


def _instantiate_template(one: Any, template_id: int, name: str) -> str:
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


def _attach_private_nic(one: Any, vm_id: str, vnet_id: str) -> None:
    """Attach the validation virtual network NIC to a VM without replacing template NICs."""
    try:
        one.vm.attachnic(int(vm_id), _private_nic_template(vnet_id))
    except AttributeError:
        one.vm.attach_nic(int(vm_id), _private_nic_template(vnet_id))


def _wait_for_vm_running(one: Any, vm_id: str, timeout: int) -> Any:
    """Wait until an OpenNebula VM reaches ACTIVE/RUNNING."""
    deadline = time.time() + timeout
    last_state = "unknown"

    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        state = int(_get_field(vm_info, "STATE", -1))
        lcm_state = int(_get_field(vm_info, "LCM_STATE", -1))
        last_state = f"{state}/{lcm_state}"
        if state == VM_RUNNING_STATE and lcm_state == VM_RUNNING_LCM_STATE:
            return vm_info
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
    """Return VM NIC records from an OpenNebula VM info object."""
    template = _get_field(vm_info, "TEMPLATE", {})
    return _as_list(_get_field(template, "NIC"))


def _nic_id(nic: Any) -> int | None:
    """Return a NIC_ID as int when present."""
    value = _get_field(nic, "NIC_ID")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _nic_ip(nic: Any) -> str | None:
    """Return a NIC IP address when present."""
    value = _get_field(nic, "IP")
    return str(value) if value else None


def _nic_network_id(nic: Any) -> str | None:
    """Return a NIC network identifier when present."""
    value = _get_field(nic, "NETWORK_ID") or _get_field(nic, "VNET_ID") or _get_field(nic, "NETWORK")
    return str(value) if value is not None else None


def _context_ip(vm_info: Any, nic_id: int) -> str | None:
    """Return an ETH<n>_IP value from VM context when present."""
    template = _get_field(vm_info, "TEMPLATE", {})
    context = _get_field(template, "CONTEXT")
    if context is None:
        return None

    for key in (f"ETH{nic_id}_IP", "PUBLIC_IP", "IP"):
        value = _get_field(context, key)
        if value:
            return str(value)

    return None


def _find_ssh_nic(nics: list[Any], ssh_nic_id: int, vnet_id: str) -> Any | None:
    """Return the configured SSH NIC, falling back to the first non-test-network NIC."""
    for nic in nics:
        if _nic_id(nic) == ssh_nic_id:
            return nic

    for nic in nics:
        if _nic_ip(nic) and _nic_network_id(nic) != str(vnet_id):
            return nic

    return None


def _find_private_nic(nics: list[Any], vnet_id: str) -> Any | None:
    """Return the NIC attached to the validation virtual network."""
    for nic in nics:
        if _nic_network_id(nic) == str(vnet_id):
            return nic

    return None


def instance_record_from_vm_info(vm_id: str, vm_info: Any, vnet_id: str, ssh_nic_id: int) -> dict[str, Any]:
    """Build the provider-neutral instance record consumed by NetworkConnectivityCheck."""
    nics = _vm_nics(vm_info)
    ssh_nic = _find_ssh_nic(nics, ssh_nic_id, vnet_id)
    private_nic = _find_private_nic(nics, vnet_id)

    public_ip = _nic_ip(ssh_nic) if ssh_nic is not None else None
    public_ip = public_ip or _context_ip(vm_info, ssh_nic_id)
    private_ip = _nic_ip(private_nic) if private_nic is not None else None
    subnet_id = _nic_network_id(private_nic) if private_nic is not None else str(vnet_id)

    return {
        "instance_id": str(vm_id),
        "subnet_id": subnet_id or str(vnet_id),
        "network_id": subnet_id or str(vnet_id),
        "private_ip": private_ip,
        "public_ip": public_ip,
        "state": "running",
    }


def _wait_for_instance_record(
    one: Any,
    vm_id: str,
    vnet_id: str,
    ssh_nic_id: int,
    timeout: int,
    interval: int = 2,
) -> dict[str, Any]:
    """Wait until a VM has both its SSH IP and validation-network private IP."""
    deadline = time.time() + timeout
    record: dict[str, Any] = {}

    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        record = instance_record_from_vm_info(vm_id, vm_info, vnet_id, ssh_nic_id)
        if record.get("public_ip") and record.get("private_ip"):
            return record
        time.sleep(interval)

    raise RuntimeError(
        f"Timed out waiting for VM {vm_id} network addresses; "
        f"public_ip={record.get('public_ip')}, private_ip={record.get('private_ip')}"
    )


def _launch_probe_vm(one: Any, template_id: int, name: str, vnet_id: str, wait_timeout: int) -> str:
    """Instantiate a probe VM, hotplug the validation NIC, and wait for it to run."""
    vm_id = _instantiate_template(one, template_id, name)
    _wait_for_vm_running(one, vm_id, wait_timeout)
    _attach_private_nic(one, vm_id, vnet_id)
    _wait_for_vm_running(one, vm_id, wait_timeout)
    return vm_id


def ssh_run(
    host: str,
    user: str,
    key_file: str,
    command: str,
    timeout: int = 30,
) -> tuple[int, str, str]:
    """Run a command over SSH and return exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",
                "-i",
                key_file,
                f"{user}@{host}",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or ""
    except Exception as e:
        return 1, "", str(e)


def wait_for_ssh(host: str, user: str, key_file: str, timeout: int, interval: int = 10) -> bool:
    """Wait for SSH to become available on a host."""
    deadline = time.time() + timeout
    attempt = 0

    while time.time() < deadline:
        attempt += 1
        exit_code, _stdout, _stderr = ssh_run(host, user, key_file, "exit 0", timeout=15)
        if exit_code == 0:
            print(f"  SSH ready after attempt {attempt}", file=sys.stderr)
            return True
        time.sleep(interval)

    print(f"  SSH not ready after {attempt} attempts", file=sys.stderr)
    return False


def _parse_ping_latency(stdout: str) -> float | None:
    """Return average ping latency from common ping output formats."""
    for line in stdout.splitlines():
        if "=" not in line or "/" not in line:
            continue
        stats = line.split("=", 1)[1].strip().split()[0].split("/")
        if len(stats) >= 2:
            try:
                return float(stats[1])
            except ValueError:
                return None
    return None


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
    """Ping a target from a VM through SSH, retrying brief datapath convergence."""
    command = f"ping -c {count} -W {ping_timeout} {shlex.quote(target)}"
    deadline = time.time() + retry_timeout
    attempt = 0
    last_error = ""

    while True:
        attempt += 1
        exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=ssh_timeout)
        if exit_code == 0:
            return {
                "passed": True,
                "latency_ms": _parse_ping_latency(stdout),
                "target": target,
                "attempts": attempt,
            }

        last_error = (stderr or stdout or f"ping exited with {exit_code}").strip()
        if time.time() >= deadline:
            break
        time.sleep(retry_interval)

    return {
        "passed": False,
        "error": last_error,
        "target": target,
        "attempts": attempt,
    }


def _cleanup_probe_vms(one: Any, vm_ids: list[str], skip_cleanup: bool) -> tuple[bool, list[str]]:
    """Terminate temporary probe VMs unless cleanup is skipped."""
    if skip_cleanup:
        return False, []

    cleanup_errors = []
    for vm_id in reversed(vm_ids):
        try:
            _terminate_vm(one, vm_id)
        except Exception as e:
            cleanup_errors.append(f"vm:{vm_id}: {e}")

    return True, cleanup_errors


def run_connectivity_test(args: argparse.Namespace, one: Any | None = None) -> dict[str, Any]:
    """Run the OpenNebula connectivity test and return the JSON contract result."""
    if not args.key_file:
        raise RuntimeError("--key-file is required for OpenNebula connectivity SSH probes")

    one = one or get_one_server(args.xmlrpc_url, args.auth)
    suffix = uuid.uuid4().hex[:8]
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "connectivity",
        "status": "failed",
        "network_id": str(args.vnet_id),
        "vpc_id": str(args.vnet_id),
        "template_id": str(args.template_id),
        "instances": [],
        "tests": {},
    }
    vm_ids: list[str] = []

    try:
        for index in range(2):
            vm_id = _launch_probe_vm(
                one,
                args.template_id,
                f"{args.name_prefix}-{index}-{suffix}",
                str(args.vnet_id),
                args.vm_wait_timeout,
            )
            vm_ids.append(vm_id)
            result["instances"].append(
                _wait_for_instance_record(one, vm_id, str(args.vnet_id), args.ssh_nic_id, args.ip_wait_timeout)
            )

        source = result["instances"][0]
        target = result["instances"][1]
        source_public_ip = source.get("public_ip")
        target_private_ip = target.get("private_ip")
        if not source_public_ip:
            raise RuntimeError(f"Source VM {source['instance_id']} has no SSH/public IP")
        if not target_private_ip:
            raise RuntimeError(f"Target VM {target['instance_id']} has no private IP")
        if not wait_for_ssh(source_public_ip, args.ssh_user, args.key_file, args.ssh_wait_timeout):
            raise RuntimeError(f"SSH not ready on source VM {source['instance_id']} at {source_public_ip}")

        result["tests"]["instance_to_instance"] = _ping_via_ssh(
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
        result["tests"]["instance_to_internet"] = _ping_via_ssh(
            host=source_public_ip,
            user=args.ssh_user,
            key_file=args.key_file,
            target=PING_TARGET_INTERNET,
            count=args.ping_count,
            ping_timeout=args.ping_timeout,
            ssh_timeout=args.ssh_command_timeout,
            retry_timeout=args.ping_retry_timeout,
            retry_interval=args.ping_retry_interval,
        )

        result["connectivity_verified"] = all(test.get("passed", False) for test in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)
        result["connectivity_verified"] = False
        result["tests"].setdefault("connectivity_error", {"passed": False, "error": str(e)})
    finally:
        cleaned_up, cleanup_errors = _cleanup_probe_vms(one, vm_ids, args.skip_cleanup)
        result["cleanup"] = cleaned_up
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            result["tests"]["cleanup"] = {"passed": False, "error": "; ".join(cleanup_errors)}

    all_tests_passed = bool(result["tests"]) and all(test.get("passed", False) for test in result["tests"].values())
    result["success"] = all_tests_passed and not result.get("cleanup_errors")
    result["status"] = "passed" if result["success"] else "failed"
    return result


def main() -> int:
    """Run OpenNebula VM connectivity probes and emit structured JSON."""
    parser = argparse.ArgumentParser(description="Test OpenNebula VM connectivity")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula VM template ID")
    parser.add_argument("--vnet-id", "--vpc-id", dest="vnet_id", required=True, help="Validation virtual network ID")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument("--ssh-nic-id", type=int, default=0, help="Template NIC_ID used for SSH access")
    parser.add_argument("--name-prefix", default="isv-connectivity", help="Temporary VM name prefix")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VMs to run")
    parser.add_argument("--ip-wait-timeout", type=int, default=120, help="Seconds to wait for VM IP assignment")
    parser.add_argument("--ssh-wait-timeout", type=int, default=300, help="Seconds to wait for SSH access")
    parser.add_argument("--ssh-command-timeout", type=int, default=30, help="Seconds allowed for each SSH ping")
    parser.add_argument("--ping-count", type=int, default=3, help="ICMP echo count")
    parser.add_argument("--ping-timeout", type=int, default=2, help="Seconds to wait for each ping reply")
    parser.add_argument("--ping-retry-timeout", type=int, default=60, help="Seconds to retry ping probes")
    parser.add_argument("--ping-retry-interval", type=int, default=5, help="Seconds between ping probe attempts")
    parser.add_argument("--skip-cleanup", action="store_true", help="Keep temporary VMs for debugging")
    args = parser.parse_args()

    try:
        result = run_connectivity_test(args)
    except Exception as e:
        result = {
            "success": False,
            "platform": "network",
            "test_name": "connectivity",
            "status": "failed",
            "network_id": str(args.vnet_id),
            "instances": [],
            "tests": {},
            "error": str(e),
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
