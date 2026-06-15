#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Reboot an OpenNebula bare-metal instance through the NICo VM lifecycle."""

import argparse
import base64
import json
import os
import shlex
import ssl
import subprocess
import sys
import time
from typing import Any
from urllib import error, parse, request

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


def env_value(name: str) -> str:
    """Return a required environment value or raise a clear error."""
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value


def as_list(value: Any) -> list[Any]:
    """Normalize a pyone scalar-or-list value to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def get_monitoring(vm_info: Any) -> dict[str, Any]:
    """Extract OpenNebula monitoring data as a plain dictionary."""
    monitoring = get_value(vm_info, "MONITORING", {})
    if isinstance(monitoring, dict):
        return dict(monitoring)
    if hasattr(monitoring, "__dict__"):
        return {key: value for key, value in vars(monitoring).items() if not key.startswith("_")}
    return {}


def get_context(template: Any) -> dict[str, Any]:
    """Extract an OpenNebula CONTEXT vector as a plain dictionary."""
    context = get_value(template, "CONTEXT", {})
    if isinstance(context, dict):
        return dict(context)
    if hasattr(context, "__dict__"):
        return {key: value for key, value in vars(context).items() if not key.startswith("_")}
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


def instance_ip(instance: dict[str, Any]) -> str | None:
    """Return the first IP address reported by NICo for the instance."""
    for nic in instance.get("interfaces") or []:
        for ip in nic.get("ipAddresses") or []:
            if ip:
                return str(ip)
    return None


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


def is_nico_ready(status: str) -> bool:
    """Return whether NICo reports the instance as ready for lifecycle checks."""
    return status in {"Ready", "BootCompleted"}


def wait_for_running(one: Any, vm_id: int, timeout: int, interval: int) -> tuple[Any, str]:
    """Wait for the VM to be RUNNING after a reboot request."""
    start_time = time.time()

    while time.time() - start_time < timeout:
        vm_info = one.vm.info(vm_id)
        state = int(get_value(vm_info, "STATE", -1))
        lcm_state = int(get_value(vm_info, "LCM_STATE", -1))
        mapped_state = map_state(state, lcm_state)

        if mapped_state == "running":
            return vm_info, mapped_state
        if mapped_state in {"failed", "terminated"}:
            raise RuntimeError(f"Instance entered {mapped_state} state {state}/{lcm_state}")

        time.sleep(interval)

    raise RuntimeError("Timeout waiting for instance to return to RUNNING state")


def ssh_ready(host: str) -> bool:
    """Return whether the instance accepts SSH commands through Teleport."""
    proxy_command = (
        f"tsh ssh --proxy={shlex.quote(env_value('ONE_BM_NICO_PROXY'))} "
        f"{shlex.quote(env_value('ONE_BM_NICO_JUMPHOST'))} nc %h %p"
    )
    ssh_command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        "-o",
        f"ProxyCommand={proxy_command}",
        f"ubuntu@{host}",
        "true",
    ]
    result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=30)
    return result.returncode == 0


def wait_for_ssh(host: str, timeout: int, interval: int) -> None:
    """Wait until SSH accepts commands after reboot."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if ssh_ready(host):
                return
        except (RuntimeError, subprocess.SubprocessError):
            pass
        time.sleep(interval)
    raise RuntimeError(f"Timed out waiting for SSH after reboot on {host}")


class NicoAPIError(RuntimeError):
    """NICo API request failed."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class NicoAPI:
    """Small NICo API client matching the OpenNebula NICo driver endpoints."""

    def __init__(self, timeout: int) -> None:
        self.carbide_proxy = env_value("ONE_BM_NICO_CARBIDE_PROXY").rstrip("/")
        self.ssa_issuer = env_value("ONE_BM_NICO_SSA_ISSUER")
        self.ngc_org = env_value("ONE_BM_NICO_NGC_ORG")
        self.client_id = env_value("ONE_BM_NICO_ISV_CLIENT_ID")
        self.client_secret = env_value("ONE_BM_NICO_ISV_CLIENT_SECRET")
        self.target_scopes = env_value("ONE_BM_NICO_TARGET_SCOPES")
        self.timeout = timeout
        self._jwt: str | None = None
        self._ssl_context = ssl._create_unverified_context()

    def acquire_jwt(self) -> str:
        """Acquire a JWT through the client_credentials flow."""
        token_url = parse.urljoin(self.ssa_issuer.rstrip("/") + "/", "/token")
        credentials = f"{self.client_id}:{self.client_secret}".encode()
        body = parse.urlencode(
            {
                "scope": self.target_scopes,
                "grant_type": "client_credentials",
            }
        ).encode()
        req = request.Request(
            token_url,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {base64.b64encode(credentials).decode()}",
            },
            method="POST",
        )

        response = self._open(req)
        token = response.get("access_token")
        if not token:
            raise NicoAPIError("JWT response did not include access_token")
        self._jwt = str(token)
        return self._jwt

    def get_instance(self, instance_id: str) -> dict[str, Any]:
        """Return a NICo instance by UUID."""
        return self._json_request("GET", f"/v2/org/{self.ngc_org}/forge/instance/{instance_id}")

    def _json_request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        jwt = self._jwt or self.acquire_jwt()
        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "Authorization": f"Bearer {jwt}",
            "Accept": "application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"

        req = request.Request(
            f"{self.carbide_proxy}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        return self._open(req)

    def _open(self, req: request.Request) -> dict[str, Any]:
        try:
            with request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                payload = resp.read().decode()
                return json.loads(payload) if payload else {}
        except error.HTTPError as e:
            payload = e.read().decode()
            raise NicoAPIError(f"NICo API HTTP {e.code}: {parse_error_body(payload)}", e.code) from e
        except error.URLError as e:
            raise NicoAPIError(f"NICo API request failed: {e.reason}") from e


def parse_error_body(body: str) -> str:
    """Return a concise API error message from a JSON or text response."""
    if not body:
        return ""
    try:
        parsed = json.loads(body)
        return str(parsed.get("message") or parsed.get("error") or parsed.get("error_description") or body)
    except json.JSONDecodeError:
        return body


def wait_for_nico_reboot(
    api: NicoAPI,
    deploy_id: str,
    before_status: str,
    timeout: int,
    interval: int,
) -> tuple[dict[str, Any], list[str]]:
    """Poll NICo until status leaves Ready and returns to Ready."""
    deadline = time.time() + timeout
    statuses: list[str] = []
    saw_transition = False
    last_instance: dict[str, Any] = {}

    while time.time() < deadline:
        last_instance = api.get_instance(deploy_id)
        status = str(last_instance.get("status") or "")
        if status and (not statuses or statuses[-1] != status):
            statuses.append(status)

        if status and not is_nico_ready(status):
            saw_transition = True
        elif is_nico_ready(status) and (saw_transition or status != before_status):
            return last_instance, statuses

        time.sleep(interval)

    raise RuntimeError(f"Timeout waiting for NICo reboot transition; statuses={statuses}")


def main() -> int:
    """Reboot an OpenNebula bare-metal instance and wait for recovery."""
    parser = argparse.ArgumentParser(description="Reboot OpenNebula bare-metal instance")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--timeout", type=int, default=1800, help="Seconds to wait for OpenNebula RUNNING")
    parser.add_argument("--nico-timeout", type=int, default=1800, help="Seconds to wait for NICo reboot status")
    parser.add_argument("--api-timeout", type=int, default=60, help="NICo API request timeout in seconds")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "instance_id": str(args.instance_id),
        "reboot_initiated": False,
        "reboot_confirmed": False,
        "ssh_ready": False,
        "nico_ready": False,
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        before_info = one.vm.info(args.instance_id)
        before_deploy_id = get_deploy_id(before_info)
        if not before_deploy_id:
            raise RuntimeError("OpenNebula VM has no NICo DEPLOY_ID")

        api = NicoAPI(args.api_timeout)
        before_instance = api.get_instance(before_deploy_id)
        before_status = str(before_instance.get("status") or "")
        result["pre_reboot_nico_status"] = before_status
        if not is_nico_ready(before_status):
            raise RuntimeError(f"NICo instance {before_deploy_id} is status {before_status}, expected Ready")

        if before_deploy_id:
            result["deploy_id"] = before_deploy_id
            result["nico_instance_id"] = before_deploy_id

        public_ip, network_id = get_ip(before_info)
        if network_id:
            result["network_id"] = network_id
            result["vpc_id"] = network_id
        if public_ip:
            result["public_ip"] = public_ip
            result["private_ip"] = public_ip

        one.vm.action("reboot", args.instance_id)
        result["reboot_initiated"] = True

        nico_instance, statuses = wait_for_nico_reboot(
            api,
            before_deploy_id,
            before_status,
            args.nico_timeout,
            args.interval,
        )
        result["nico_statuses"] = statuses
        result["nico_status"] = str(nico_instance.get("status") or "")
        result["nico_ready"] = is_nico_ready(result["nico_status"])
        if nico_instance.get("machineId"):
            result["machine_id"] = str(nico_instance["machineId"])

        time.sleep(args.interval)
        vm_info, state = wait_for_running(one, args.instance_id, args.timeout, args.interval)
        result["state"] = state
        result["opennebula_recovered"] = True

        deploy_id = get_deploy_id(vm_info)
        if deploy_id:
            result["deploy_id"] = deploy_id
            result["nico_instance_id"] = deploy_id
        if deploy_id != before_deploy_id:
            raise RuntimeError(f"NICo DEPLOY_ID changed after reboot: {before_deploy_id} -> {deploy_id}")

        monitoring = get_monitoring(vm_info)
        if monitoring.get("NICO_STATUS"):
            result["opennebula_nico_status"] = str(monitoring["NICO_STATUS"])
        if monitoring.get("MACHINE_ID"):
            result["machine_id"] = str(monitoring["MACHINE_ID"])

        public_ip, network_id = get_ip(vm_info)
        public_ip = public_ip or instance_ip(nico_instance)
        if public_ip:
            result["public_ip"] = public_ip
            result["private_ip"] = public_ip
        result["ssh_user"] = "ubuntu"
        if os.environ.get("ONE_BM_NICO_PROXY") and os.environ.get("ONE_BM_NICO_JUMPHOST"):
            result["ssh_proxy"] = os.environ["ONE_BM_NICO_PROXY"]
            result["ssh_jumphost"] = os.environ["ONE_BM_NICO_JUMPHOST"]
        if network_id:
            result["network_id"] = network_id
            result["vpc_id"] = network_id

        if not public_ip:
            raise RuntimeError("OpenNebula VM has no IP after reboot")
        wait_for_ssh(public_ip, args.timeout, args.interval)
        result["ssh_ready"] = True

        result["reboot_confirmed"] = True
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
