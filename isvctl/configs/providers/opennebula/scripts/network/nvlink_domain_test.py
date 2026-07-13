#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate NVLink fabric metadata from a temporary OpenNebula GPU VM."""

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

from common.network import get_one_server
from test_connectivity import (
    _context_ip,
    _instantiate_template,
    _nic_id,
    _nic_ip,
    _terminate_vm,
    _vm_nics,
    _wait_for_vm_running,
    ssh_run,
    wait_for_ssh,
)

CLUSTER_UUID_RE = re.compile(r"^\s*ClusterUUID\s*:\s*(\S+)\s*$", re.MULTILINE)
FABRIC_STATE_RE = re.compile(r"^\s*State\s*:\s*(.+?)\s*$", re.MULTILINE)
FABRIC_STATUS_RE = re.compile(r"^\s*Status\s*:\s*(.+?)\s*$", re.MULTILINE)
FABRIC_HEALTH_RE = re.compile(r"^\s*Summary\s*:\s*(.+?)\s*$", re.MULTILINE)


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


def _base_result(region: str) -> dict[str, Any]:
    """Build the NvlinkDomainCheck output envelope."""
    return {
        "success": False,
        "platform": "network",
        "test_name": "nvlink_domain",
        "region": region,
        "node_id": "",
        "nvlink_supported": False,
        "tests": {
            "node_resolved": _failed("not run"),
            "nvlink_support_detected": _failed("not run"),
            "nvlink_domain_id_present": _failed("not run"),
        },
    }


def _find_nic_ip(vm_info: Any, nic_id: int) -> str | None:
    """Return the requested NIC IP or a contextualized IP fallback."""
    for nic in _vm_nics(vm_info):
        if _nic_id(nic) == nic_id:
            ip = _nic_ip(nic)
            if ip:
                return ip
    return _context_ip(vm_info, nic_id)


def _wait_for_ssh_ip(one: Any, vm_id: str, nic_id: int, timeout: int, interval: int = 2) -> str:
    """Wait until the selected VM NIC has an IP address."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        vm_info = one.vm.info(int(vm_id))
        ip = _find_nic_ip(vm_info, nic_id)
        if ip:
            return ip
        time.sleep(interval)
    raise RuntimeError(f"Timed out waiting for VM {vm_id} NIC {nic_id} to receive an IP")


def _run_required(host: str, user: str, key_file: str, command: str, timeout: int) -> str:
    """Run SSH command and raise with concise diagnostics on failure."""
    exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=timeout)
    if exit_code != 0:
        detail = (stderr or stdout or f"command exited with {exit_code}").strip()
        raise RuntimeError(detail)
    return stdout


def _fabric_field(pattern: re.Pattern[str], output: str) -> str:
    """Return a Fabric field from nvidia-smi -q output."""
    match = pattern.search(output)
    return match.group(1).strip() if match else ""


def _fabric_block(output: str) -> str:
    """Return the Fabric section from nvidia-smi -q output."""
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "Fabric":
            continue

        block: list[str] = []
        for item in lines[index + 1 :]:
            if item.strip() and not item.startswith(" "):
                break
            block.append(item)
        return "\n".join(block)

    return ""


def run_nvlink_domain_test(args: argparse.Namespace) -> dict[str, Any]:
    """Launch a GPU VM and emit NVLink domain metadata."""
    if not args.key_file:
        raise RuntimeError("--key-file is required for OpenNebula NVLink domain validation")

    one = get_one_server(args.xmlrpc_url, args.auth)
    suffix = uuid.uuid4().hex[:8]
    vm_id: str | None = None
    result = _base_result(args.region)

    try:
        vm_id = _instantiate_template(one, args.template_id, f"{args.name_prefix}-{suffix}")
        result["node_id"] = vm_id
        result["instance_id"] = vm_id
        result["tests"]["node_resolved"] = _passed("OpenNebula NVLink probe VM instantiated", instance_id=vm_id)

        _wait_for_vm_running(one, vm_id, args.vm_wait_timeout)
        host = _wait_for_ssh_ip(one, vm_id, args.ssh_nic_id, args.ip_wait_timeout)
        result["ssh_host"] = host
        result["ssh_nic_id"] = args.ssh_nic_id

        if not wait_for_ssh(host, args.ssh_user, args.key_file, args.ssh_wait_timeout):
            raise RuntimeError(f"SSH not ready on VM {vm_id} at {host}")

        _run_required(host, args.ssh_user, args.key_file, "command -v nvidia-smi", 30)
        output = _run_required(host, args.ssh_user, args.key_file, "nvidia-smi -q", args.ssh_command_timeout)

        fabric_output = _fabric_block(output)
        cluster_uuid = _fabric_field(CLUSTER_UUID_RE, fabric_output)
        fabric_state = _fabric_field(FABRIC_STATE_RE, fabric_output)
        fabric_status = _fabric_field(FABRIC_STATUS_RE, fabric_output)
        fabric_health = _fabric_field(FABRIC_HEALTH_RE, fabric_output)

        result["fabric"] = {
            "state": fabric_state,
            "status": fabric_status,
            "health_summary": fabric_health,
            "cluster_uuid": cluster_uuid,
        }
        result["nvlink_supported"] = bool(cluster_uuid)
        result["tests"]["nvlink_support_detected"] = (
            _passed("nvidia-smi reported NVLink fabric metadata", fabric=result["fabric"])
            if cluster_uuid
            else _failed("nvidia-smi did not report a Fabric ClusterUUID", fabric=result["fabric"])
        )

        if cluster_uuid:
            result["nvlink_domain_id"] = cluster_uuid
            result["tests"]["nvlink_domain_id_present"] = _passed(
                "NVLink ClusterUUID present in nvidia-smi fabric metadata",
                nvlink_domain_id=cluster_uuid,
            )
        else:
            result["tests"]["nvlink_domain_id_present"] = _failed("NVLink ClusterUUID missing")

        result["success"] = all(test.get("passed", False) for test in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)
        result["tests"].setdefault("nvlink_domain_error", _failed(str(e)))
    finally:
        if vm_id and not args.skip_destroy:
            try:
                _terminate_vm(one, vm_id)
                result["cleanup"] = {"instance": "deleted"}
            except Exception as e:
                result["cleanup"] = {"instance": f"failed: {e}"}
        elif vm_id:
            result["cleanup"] = {"instance": "skipped"}

    return result


def main() -> int:
    """Run OpenNebula NVLink domain validation."""
    parser = argparse.ArgumentParser(description="OpenNebula NVLink domain metadata validation")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula GPU VM template ID")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument("--ssh-nic-id", type=int, default=0, help="NIC_ID used as SSH target")
    parser.add_argument("--name-prefix", default="isv-nvlink-domain", help="Temporary VM name prefix")
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VM to run")
    parser.add_argument("--ip-wait-timeout", type=int, default=120, help="Seconds to wait for VM IP assignment")
    parser.add_argument("--ssh-wait-timeout", type=int, default=300, help="Seconds to wait for SSH access")
    parser.add_argument("--ssh-command-timeout", type=int, default=60, help="Seconds allowed for SSH commands")
    parser.add_argument("--skip-destroy", action="store_true", help="Keep the temporary VM for debugging")
    args = parser.parse_args()

    try:
        result = run_nvlink_domain_test(args)
    except Exception as e:
        result = _base_result(args.region)
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
