#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Verify a NICo bare-metal instance image by SSH through Teleport jumphost."""

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


def map_opennebula_state(state: int, lcm_state: int) -> str:
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
        body = parse.urlencode({"scope": self.target_scopes, "grant_type": "client_credentials"}).encode()
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
        headers = {"Authorization": f"Bearer {jwt}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"

        req = request.Request(f"{self.carbide_proxy}{path}", data=data, headers=headers, method=method)
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


def instance_ip(instance: dict[str, Any]) -> str | None:
    """Return the first NICo interface IP address, if present."""
    for nic in instance.get("interfaces") or []:
        for ip in nic.get("ipAddresses") or []:
            if ip:
                return str(ip)
    return None


def ssh_run(host: str, user: str, command: str, timeout: int) -> tuple[int, str, str]:
    """Run an SSH command through Teleport jumphost and return rc/stdout/stderr."""
    proxy = env_value("ONE_BM_NICO_PROXY")
    jumphost = env_value("ONE_BM_NICO_JUMPHOST")
    proxy_command = f"tsh ssh --proxy={shlex.quote(proxy)} {shlex.quote(jumphost)} nc %h %p"
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
        f"{user}@{host}",
        command,
    ]
    result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def ssh_run_with_retry(
    host: str,
    user: str,
    command: str,
    timeout: int,
    wait_timeout: int,
    interval: int = 15,
) -> tuple[int, str, str]:
    """Retry SSH while the freshly provisioned guest finishes booting."""
    deadline = time.time() + wait_timeout
    last_result = (1, "", "SSH was not attempted")

    while time.time() < deadline:
        try:
            last_result = ssh_run(host, user, command, timeout)
            if last_result[0] == 0:
                return last_result
        except subprocess.TimeoutExpired as e:
            last_result = (124, e.stdout or "", e.stderr or "")

        time.sleep(interval)

    return last_result


def parse_os_release(value: str) -> dict[str, str]:
    """Parse /etc/os-release key/value content."""
    parsed: dict[str, str] = {}
    for line in value.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        parsed[key] = raw_value.strip().strip('"')
    return parsed


def main() -> int:
    """Verify image installation by querying OpenNebula/NICo and SSHing into the instance."""
    parser = argparse.ArgumentParser(description="Verify OpenNebula BM image over SSH")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--api-timeout", type=int, default=60, help="NICo API request timeout in seconds")
    parser.add_argument("--ssh-timeout", type=int, default=60, help="SSH command timeout in seconds")
    parser.add_argument("--ssh-wait-timeout", type=int, default=60, help="Seconds to wait for SSH readiness")
    args = parser.parse_args()
    ssh_user = "ubuntu"

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")
    result: dict[str, Any] = {
        "success": False,
        "platform": "image_registry",
        "instance_id": str(args.instance_id),
        "ssh_user": ssh_user,
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        vm_info = one.vm.info(args.instance_id)
        state = int(get_value(vm_info, "STATE", -1))
        lcm_state = int(get_value(vm_info, "LCM_STATE", -1))
        result["instance_state"] = map_opennebula_state(state, lcm_state)
        result["state"] = result["instance_state"]

        if result["instance_state"] != "running":
            raise RuntimeError(f"Instance is {result['instance_state']}, expected running")

        deploy_id = get_deploy_id(vm_info)
        if not deploy_id:
            raise RuntimeError("OpenNebula VM has no NICo DEPLOY_ID")
        result["deploy_id"] = deploy_id
        result["nico_instance_id"] = deploy_id

        nico_instance = NicoAPI(args.api_timeout).get_instance(deploy_id)
        nico_status = str(nico_instance.get("status") or "")
        result["nico_status"] = nico_status
        result["nico_ready"] = nico_status == "Ready"
        if nico_status != "Ready":
            raise RuntimeError(f"NICo instance is {nico_status}, expected Ready")

        host = instance_ip(nico_instance)
        if not host:
            monitoring = get_monitoring(vm_info)
            host = str(monitoring.get("NIC0_IP") or monitoring.get("PUBLIC_IP") or monitoring.get("IP") or "")
        if not host:
            raise RuntimeError("No instance IP found in NICo interfaces or OpenNebula monitoring")
        result["public_ip"] = host
        result["private_ip"] = host

        command = "cat /etc/os-release && printf '\\n__UNAME_M__=' && uname -m"
        exit_code, stdout, stderr = ssh_run_with_retry(
            host,
            ssh_user,
            command,
            args.ssh_timeout,
            args.ssh_wait_timeout,
        )
        result["ssh_exit_code"] = exit_code
        if exit_code != 0:
            raise RuntimeError(f"SSH image verification failed: {stderr.strip() or stdout.strip()}")

        os_release, _, uname_line = stdout.partition("__UNAME_M__=")
        os_info = parse_os_release(os_release)
        architecture = uname_line.strip().splitlines()[0] if uname_line.strip() else ""

        result["image_id"] = os_info.get("VERSION_CODENAME") or os_info.get("VERSION_ID") or ""
        result["image_name"] = os_info.get("PRETTY_NAME") or os_info.get("NAME") or ""
        result["image_architecture"] = architecture
        result["image_description"] = os_info.get("VERSION", "")
        result["os_id"] = os_info.get("ID", "")
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
