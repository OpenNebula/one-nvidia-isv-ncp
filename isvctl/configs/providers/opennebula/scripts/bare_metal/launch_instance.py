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
import ssl
import sys
import time
import uuid
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


def quote(value: object) -> str:
    """Render a quoted OpenNebula template value."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_tag_template(name: str) -> str:
    """Build provider-neutral tag attributes in the VM USER_TEMPLATE."""
    return "\n".join(
        [
            f"ISV_TAG_NAME = {quote(name)}",
            'ISV_TAG_CREATED_BY = "isvtest"',
        ]
    )


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

    while time.time() - start_time < timeout:
        vm_info = one.vm.info(vm_id)
        monitoring = get_monitoring(vm_info)
        deploy_id = get_deploy_id(vm_info)
        nico_status = str(monitoring.get("NICO_STATUS", ""))

        if deploy_id:
            return vm_info, deploy_id, monitoring

        if nico_status in {"Error", "Failed"}:
            raise RuntimeError(f"NICo instance entered {nico_status} state")

        time.sleep(15)

    raise RuntimeError("Timeout waiting for NICo DEPLOY_ID")


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


def instance_ip(instance: dict[str, Any]) -> str | None:
    """Return the first NICo interface IP address, if present."""
    for nic in instance.get("interfaces") or []:
        for ip in nic.get("ipAddresses") or []:
            if ip:
                return str(ip)
    return None


def wait_for_nico_ready(
    api: NicoAPI,
    deploy_id: str,
    timeout: int,
    interval: int,
) -> tuple[dict[str, Any], list[str]]:
    """Poll NICo until the instance reaches Ready."""
    deadline = time.time() + timeout
    statuses: list[str] = []
    last_instance: dict[str, Any] = {}

    while time.time() < deadline:
        last_instance = api.get_instance(deploy_id)
        status = str(last_instance.get("status") or "")
        if status and (not statuses or statuses[-1] != status):
            statuses.append(status)

        if status == "Ready":
            return last_instance, statuses
        if status in {"Error", "Failed"}:
            raise RuntimeError(f"NICo instance entered {status} state")

        time.sleep(interval)

    raise RuntimeError(f"Timeout waiting for NICo instance to become Ready; statuses={statuses}")


def populate_result_from_vm(
    result: dict[str, Any],
    one: Any,
    vm_info: Any,
    deploy_id: str,
    monitoring: dict[str, Any],
    nico_instance: dict[str, Any],
    nico_statuses: list[str],
) -> None:
    """Populate provider-neutral launch output from an OpenNebula/NICo VM."""
    template = get_value(vm_info, "TEMPLATE", {})
    context = get_context(template)
    user_key = get_user_ssh_public_key(one, vm_info)
    context_key = str(context.get("SSH_PUBLIC_KEY", "") or "")
    requested_key_names = public_key_fingerprints(user_key)
    observed_key_names = public_key_fingerprints(context_key)

    result["nico_instance_id"] = deploy_id
    result["deploy_id"] = deploy_id
    public_ip, network_id = get_ip(vm_info)
    public_ip = instance_ip(nico_instance) or public_ip
    if public_ip:
        result["public_ip"] = public_ip
        result["private_ip"] = public_ip
    result["nico_status"] = str(nico_instance.get("status") or "")
    result["nico_statuses"] = nico_statuses
    result["nico_ready"] = result["nico_status"] == "Ready"
    if monitoring.get("NICO_STATUS"):
        result["opennebula_nico_status"] = str(monitoring["NICO_STATUS"])
    if nico_instance.get("machineId"):
        result["machine_id"] = str(nico_instance["machineId"])
    elif monitoring.get("MACHINE_ID"):
        result["machine_id"] = str(monitoring["MACHINE_ID"])
    if network_id:
        result["network_id"] = network_id
        result["vpc_id"] = network_id

    result["requested_key_name"] = ",".join(requested_key_names)
    result["key_name"] = ",".join(observed_key_names)
    result["contextualization_completed"] = bool(context)
    result["ssh_user"] = "ubuntu"
    if os.environ.get("ONE_BM_NICO_PROXY") and os.environ.get("ONE_BM_NICO_JUMPHOST"):
        result["ssh_proxy"] = os.environ["ONE_BM_NICO_PROXY"]
        result["ssh_jumphost"] = os.environ["ONE_BM_NICO_JUMPHOST"]
    result["tests"] = {
        "specified_key": {
            "passed": bool(requested_key_names) and requested_key_names == observed_key_names,
            "message": "CONTEXT/SSH_PUBLIC_KEY matches user TEMPLATE/SSH_PUBLIC_KEY"
            if requested_key_names == observed_key_names
            else "CONTEXT/SSH_PUBLIC_KEY does not match user TEMPLATE/SSH_PUBLIC_KEY",
            "probes": ["user_ssh_public_key", "context_ssh_public_key"],
        }
    }


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
    parser.add_argument(
        "--nico-ready-timeout",
        type=int,
        default=3600,
        help="Seconds to wait for NICo instance Ready status",
    )
    parser.add_argument("--api-timeout", type=int, default=60, help="NICo API request timeout in seconds")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    args = parser.parse_args()
    existing_instance_id = os.environ.get("ONE_BM_EXISTING_INSTANCE_ID", "")
    instance_name = f"{args.name}-{uuid.uuid4().hex[:8]}"

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "instance_id": None,
        "instance_type": str(args.template_id),
        "name": instance_name,
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        if existing_instance_id:
            vm_id = int(existing_instance_id)
            vm_info = one.vm.info(vm_id)
            result["instance_id"] = str(vm_id)
            result["name"] = str(get_value(vm_info, "NAME", "")) or f"one-{vm_id}"
            result["existing_instance"] = True
            one.vm.update(vm_id, build_tag_template(result["name"]), 1)
        else:
            vm_id = one.template.instantiate(args.template_id, instance_name)
            vm_info = None
            result["instance_id"] = str(vm_id)
            one.vm.update(vm_id, build_tag_template(instance_name), 1)

        start_time = time.time()
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
        api = NicoAPI(args.api_timeout)
        nico_instance, nico_statuses = wait_for_nico_ready(
            api,
            deploy_id,
            args.nico_ready_timeout,
            args.interval,
        )
        populate_result_from_vm(result, one, vm_info, deploy_id, monitoring, nico_instance, nico_statuses)

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
