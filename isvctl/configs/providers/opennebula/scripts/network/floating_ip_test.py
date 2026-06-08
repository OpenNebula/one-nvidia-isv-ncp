#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula floating IP behavior with a NIC alias."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.network import get_one_server  # noqa: E402
from test_connectivity import (  # noqa: E402
    _as_list,
    _get_field,
    _instantiate_template,
    _nic_id,
    _nic_ip,
    _nic_network_id,
    _terminate_vm,
    _vm_nics,
    _wait_for_vm_running,
)

FLOATING_IP_TESTS = (
    "allocate_eip",
    "associate_to_a",
    "verify_on_a",
    "reassociate_to_b",
    "verify_on_b",
    "verify_not_on_a",
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


def _onevm_command(args: argparse.Namespace, command: list[str], timeout: int = 60) -> None:
    """Run a onevm command using the current OpenNebula CLI context."""
    full_command = ["onevm", *command]

    try:
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise RuntimeError("onevm CLI is not installed or not in PATH") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"onevm command timed out: {' '.join(full_command[:3])}") from e

    if result.returncode != 0:
        details = (result.stderr or result.stdout or f"exit={result.returncode}").strip()
        raise RuntimeError(f"onevm command failed: {details}")


def _alias_records(vm_info: Any) -> list[Any]:
    """Return NIC_ALIAS records from a VM info object."""
    template = _get_field(vm_info, "TEMPLATE", {})
    return _as_list(_get_field(template, "NIC_ALIAS"))


def _network_records(vm_info: Any) -> list[Any]:
    """Return all NIC and NIC_ALIAS records from a VM info object."""
    return [*_vm_nics(vm_info), *_alias_records(vm_info)]


def _find_ip_record(vm_info: Any, network_id: str, ip: str) -> Any | None:
    """Find a NIC/NIC_ALIAS record by network ID and IP."""
    for record in _network_records(vm_info):
        if _nic_ip(record) == ip and _nic_network_id(record) == str(network_id):
            return record
    return None


def _alias_nic_id(one: Any, vm_id: str, network_id: str, ip: str) -> int | None:
    """Return the NIC_ID for the floating IP alias if present."""
    record = _find_ip_record(one.vm.info(int(vm_id)), network_id, ip)
    return _nic_id(record) if record is not None else None


def _wait_for_alias_state(
    one: Any,
    vm_id: str,
    network_id: str,
    ip: str,
    *,
    present: bool,
    timeout: int,
    interval: int = 2,
) -> int | None:
    """Wait until the floating IP alias is present or absent on a VM."""
    deadline = time.time() + timeout
    nic_id: int | None = None

    while time.time() < deadline:
        nic_id = _alias_nic_id(one, vm_id, network_id, ip)
        if (nic_id is not None) is present:
            return nic_id
        time.sleep(interval)

    return nic_id


def _attach_alias(args: argparse.Namespace, vm_id: str) -> None:
    """Attach the configured floating IP alias to a VM."""
    _onevm_command(
        args,
        [
            "nic-attach",
            str(vm_id),
            "-a",
            args.alias_parent,
            "-n",
            str(args.floating_network_id),
            "-i",
            args.floating_ip,
        ],
    )


def _detach_alias(args: argparse.Namespace, vm_id: str, nic_id: int) -> None:
    """Detach a floating IP alias NIC from a VM."""
    _onevm_command(args, ["nic-detach", str(vm_id), str(nic_id)])


def _detach_alias_if_present(args: argparse.Namespace, one: Any, vm_id: str) -> bool:
    """Detach the floating IP alias from a VM if present."""
    nic_id = _alias_nic_id(one, vm_id, str(args.floating_network_id), args.floating_ip)
    if nic_id is None:
        return False
    _detach_alias(args, vm_id, nic_id)
    _wait_for_alias_state(
        one,
        vm_id,
        str(args.floating_network_id),
        args.floating_ip,
        present=False,
        timeout=args.alias_wait_timeout,
    )
    return True


def run_floating_ip_test(args: argparse.Namespace, one: Any | None = None) -> dict[str, Any]:
    """Run the OpenNebula floating IP alias switch test."""
    one = one or get_one_server(args.xmlrpc_url, args.auth)
    suffix = uuid.uuid4().hex[:8]
    vm_ids: list[str] = []
    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "floating_ip",
        "status": "failed",
        "tests": {name: _failed("not run") for name in FLOATING_IP_TESTS},
    }

    try:
        for label in ("a", "b"):
            vm_id = _instantiate_template(one, args.template_id, f"{args.name_prefix}-{label}-{suffix}")
            vm_ids.append(vm_id)
            _wait_for_vm_running(one, vm_id, args.vm_wait_timeout)

        vm_a, vm_b = vm_ids
        result["instances"] = [{"instance_id": vm_a, "label": "a"}, {"instance_id": vm_b, "label": "b"}]
        result["tests"]["allocate_eip"] = _passed(
            "Using configured OpenNebula NIC alias IP",
            allocation_id=f"opennebula-nic-alias:{args.floating_network_id}:{args.floating_ip}",
            public_ip=args.floating_ip,
            network_id=str(args.floating_network_id),
        )

        _attach_alias(args, vm_a)
        alias_a = _wait_for_alias_state(
            one,
            vm_a,
            str(args.floating_network_id),
            args.floating_ip,
            present=True,
            timeout=args.alias_wait_timeout,
        )
        if alias_a is None:
            raise RuntimeError(f"Floating IP {args.floating_ip} did not appear on VM {vm_a}")
        result["tests"]["associate_to_a"] = _passed(
            "Floating IP alias associated to VM A",
            instance_id=vm_a,
            nic_id=alias_a,
            public_ip=args.floating_ip,
        )

        result["tests"]["verify_on_a"] = (
            _passed("Floating IP alias present on VM A", instance_id=vm_a, public_ip=args.floating_ip, nic_id=alias_a)
            if _alias_nic_id(one, vm_a, str(args.floating_network_id), args.floating_ip) is not None
            else _failed("Floating IP alias not present on VM A", instance_id=vm_a, public_ip=args.floating_ip)
        )

        start = time.monotonic()
        _detach_alias(args, vm_a, alias_a)
        _wait_for_alias_state(
            one,
            vm_a,
            str(args.floating_network_id),
            args.floating_ip,
            present=False,
            timeout=args.alias_wait_timeout,
        )
        _attach_alias(args, vm_b)
        alias_b = _wait_for_alias_state(
            one,
            vm_b,
            str(args.floating_network_id),
            args.floating_ip,
            present=True,
            timeout=args.alias_wait_timeout,
        )
        switch_seconds = round(time.monotonic() - start, 2)
        if alias_b is None:
            result["tests"]["reassociate_to_b"] = _failed(
                "Floating IP alias did not appear on VM B",
                switch_seconds=switch_seconds,
                public_ip=args.floating_ip,
            )
        elif switch_seconds > args.max_switch_seconds:
            result["tests"]["reassociate_to_b"] = _failed(
                f"Floating IP alias switch took {switch_seconds}s, limit is {args.max_switch_seconds}s",
                switch_seconds=switch_seconds,
                public_ip=args.floating_ip,
                nic_id=alias_b,
            )
        else:
            result["tests"]["reassociate_to_b"] = _passed(
                "Floating IP alias reassociated to VM B",
                switch_seconds=switch_seconds,
                public_ip=args.floating_ip,
                nic_id=alias_b,
            )

        result["tests"]["verify_on_b"] = (
            _passed("Floating IP alias present on VM B", instance_id=vm_b, public_ip=args.floating_ip, nic_id=alias_b)
            if _alias_nic_id(one, vm_b, str(args.floating_network_id), args.floating_ip) is not None
            else _failed("Floating IP alias not present on VM B", instance_id=vm_b, public_ip=args.floating_ip)
        )
        result["tests"]["verify_not_on_a"] = (
            _passed("Floating IP alias removed from VM A", instance_id=vm_a, public_ip=args.floating_ip)
            if _alias_nic_id(one, vm_a, str(args.floating_network_id), args.floating_ip) is None
            else _failed("Floating IP alias still present on VM A", instance_id=vm_a, public_ip=args.floating_ip)
        )

    except Exception as e:
        result["error"] = str(e)
        for name, test in result["tests"].items():
            if not test.get("passed") and test.get("error") == "not run":
                result["tests"][name] = _failed(str(e))
                break
    finally:
        cleanup_errors = []
        for vm_id in vm_ids:
            try:
                _detach_alias_if_present(args, one, vm_id)
            except Exception as e:
                cleanup_errors.append(f"alias:{vm_id}: {e}")
        for vm_id in reversed(vm_ids):
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
    """Run OpenNebula floating IP alias validation."""
    parser = argparse.ArgumentParser(description="Test OpenNebula floating IP alias switch")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula VM template ID")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--floating-ip", default="192.168.150.147", help="Free IP to use as NIC alias")
    parser.add_argument("--floating-network-id", default="0", help="OpenNebula network ID for the alias")
    parser.add_argument("--alias-parent", default="NIC0", help="Parent NIC name used by onevm nic-attach -a")
    parser.add_argument("--max-switch-seconds", type=int, default=10, help="Validation threshold consumed upstream")
    parser.add_argument("--name-prefix", default="isv-floating-ip", help="Temporary VM name prefix")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VMs to run")
    parser.add_argument("--alias-wait-timeout", type=int, default=120, help="Seconds to wait for alias state")
    args = parser.parse_args()

    try:
        result = run_floating_ip_test(args)
    except Exception as e:
        result = {
            "success": False,
            "platform": "network",
            "test_name": "floating_ip",
            "status": "failed",
            "tests": {name: _failed(str(e)) for name in FLOATING_IP_TESTS},
            "error": str(e),
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
