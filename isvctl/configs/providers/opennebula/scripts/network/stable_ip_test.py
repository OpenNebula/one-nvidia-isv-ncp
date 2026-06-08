#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula private IP stability across VM poweroff/resume."""

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
    VM_DONE_STATE,
    _get_field,
    _instantiate_template,
    _nic_id,
    _nic_ip,
    _terminate_vm,
    _vm_nics,
    _wait_for_vm_running,
)

VM_POWEROFF_STATE = 8
STABLE_IP_TESTS = ("create_instance", "record_ip", "stop_instance", "start_instance", "ip_unchanged")


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


def _wait_for_nic_ip(one: Any, vm_id: str, nic_id: int, timeout: int, interval: int = 2) -> str:
    """Wait until the requested NIC has an IP address."""
    deadline = time.time() + timeout
    last_ips: list[str] = []

    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        last_ips = [_nic_ip(nic) or "" for nic in _vm_nics(vm_info)]
        nic = _find_nic_by_id(vm_info, nic_id)
        ip = _nic_ip(nic) if nic is not None else None
        if ip:
            return ip
        time.sleep(interval)

    raise RuntimeError(f"Timed out waiting for VM {vm_id} NIC {nic_id} IP; observed IPs={last_ips}")


def _wait_for_vm_poweroff(one: Any, vm_id: str, timeout: int, interval: int = 5) -> None:
    """Wait until a VM reaches OpenNebula POWEROFF state."""
    deadline = time.time() + timeout
    last_state = "unknown"

    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        state = int(_get_field(vm_info, "STATE", -1))
        lcm_state = int(_get_field(vm_info, "LCM_STATE", -1))
        last_state = f"{state}/{lcm_state}"
        if state == VM_POWEROFF_STATE:
            return
        if state == VM_DONE_STATE:
            raise RuntimeError(f"VM {vm_id} reached DONE while waiting for poweroff")
        time.sleep(interval)

    raise TimeoutError(f"Timed out waiting for VM {vm_id} poweroff; last state {last_state}")


def run_stable_ip_test(args: argparse.Namespace, one: Any | None = None) -> dict[str, Any]:
    """Run private IP stability probes and return the JSON contract result."""
    one = one or get_one_server(args.xmlrpc_url, args.auth)
    suffix = uuid.uuid4().hex[:8]
    vm_id: str | None = None
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "stable_ip",
        "status": "failed",
        "tests": {name: _failed("not run") for name in STABLE_IP_TESTS},
    }

    try:
        vm_id = _instantiate_template(one, args.template_id, f"{args.name_prefix}-{suffix}")
        _wait_for_vm_running(one, vm_id, args.vm_wait_timeout)
        result["tests"]["create_instance"] = _passed("VM launched", instance_id=vm_id)

        ip_before = _wait_for_nic_ip(one, vm_id, args.private_nic_id, args.ip_wait_timeout)
        result["tests"]["record_ip"] = _passed(
            "Recorded private NIC IP",
            instance_id=vm_id,
            nic_id=args.private_nic_id,
            private_ip=ip_before,
        )

        one.vm.action("poweroff", int(vm_id))
        _wait_for_vm_poweroff(one, vm_id, args.vm_wait_timeout)
        result["tests"]["stop_instance"] = _passed("VM powered off", instance_id=vm_id)

        one.vm.action("resume", int(vm_id))
        _wait_for_vm_running(one, vm_id, args.vm_wait_timeout)
        result["tests"]["start_instance"] = _passed("VM resumed", instance_id=vm_id)

        ip_after = _wait_for_nic_ip(one, vm_id, args.private_nic_id, args.ip_wait_timeout)
        result["tests"]["ip_unchanged"] = (
            _passed("Private IP unchanged after poweroff/resume", ip_before=ip_before, ip_after=ip_after)
            if ip_after == ip_before
            else _failed("Private IP changed after poweroff/resume", ip_before=ip_before, ip_after=ip_after)
        )

    except Exception as e:
        result["error"] = str(e)
        for name, test in result["tests"].items():
            if not test.get("passed") and test.get("error") == "not run":
                result["tests"][name] = _failed(str(e))
                break
    finally:
        cleanup_errors = []
        if vm_id:
            try:
                _terminate_vm(one, vm_id)
            except Exception as e:
                cleanup_errors.append(f"vm:{vm_id}: {e}")
        result["cleanup"] = not cleanup_errors
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors

        result["success"] = all(test.get("passed", False) for test in result["tests"].values()) and not cleanup_errors
        result["status"] = "passed" if result["success"] else "failed"

    return result


def main() -> int:
    """Run OpenNebula stable private IP validation."""
    parser = argparse.ArgumentParser(description="Test OpenNebula private IP stability")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula VM template ID")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--private-nic-id", type=int, default=1, help="NIC_ID whose IP must remain stable")
    parser.add_argument("--name-prefix", default="isv-stable-ip", help="Temporary VM name prefix")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VM state changes")
    parser.add_argument("--ip-wait-timeout", type=int, default=120, help="Seconds to wait for NIC IP assignment")
    args = parser.parse_args()

    try:
        result = run_stable_ip_test(args)
    except Exception as e:
        result = {
            "success": False,
            "platform": "network",
            "test_name": "stable_ip",
            "status": "failed",
            "tests": {name: _failed(str(e)) for name in STABLE_IP_TESTS},
            "error": str(e),
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
