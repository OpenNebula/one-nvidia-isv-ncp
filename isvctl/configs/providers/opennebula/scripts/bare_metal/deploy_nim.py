#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Deploy a NIM container on an OpenNebula/NICo bare-metal instance."""

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


def env_value(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value


def get_value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def get_deploy_id(vm_info: Any) -> str | None:
    deploy_id = get_value(vm_info, "DEPLOY_ID")
    if deploy_id:
        return str(deploy_id)
    history = get_value(get_value(vm_info, "HISTORY_RECORDS", {}), "HISTORY")
    for record in reversed(as_list(history)):
        deploy_id = get_value(record, "VM_MAD_DEPLOY_ID") or get_value(record, "DEPLOY_ID")
        if deploy_id:
            return str(deploy_id)
    return None


class NicoAPI:
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
            raise RuntimeError("JWT response did not include access_token")
        self._jwt = str(token)
        return self._jwt

    def get_instance(self, instance_id: str) -> dict[str, Any]:
        jwt = self._jwt or self.acquire_jwt()
        req = request.Request(
            f"{self.carbide_proxy}/v2/org/{self.ngc_org}/forge/instance/{instance_id}",
            headers={"Authorization": f"Bearer {jwt}", "Accept": "application/json"},
            method="GET",
        )
        return self._open(req)

    def _open(self, req: request.Request) -> dict[str, Any]:
        try:
            with request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                payload = resp.read().decode()
                return json.loads(payload) if payload else {}
        except error.HTTPError as e:
            raise RuntimeError(f"NICo API HTTP {e.code}: {e.read().decode()}") from e
        except error.URLError as e:
            raise RuntimeError(f"NICo API request failed: {e.reason}") from e


def instance_ip(instance: dict[str, Any]) -> str | None:
    for nic in instance.get("interfaces") or []:
        for ip in nic.get("ipAddresses") or []:
            if ip:
                return str(ip)
    return None


def resolve_instance(instance_id: int, api_timeout: int) -> tuple[str, str]:
    one = pyone.OneServer(
        os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"),
        session=os.environ.get("ONE_AUTH", "oneadmin:opennebula"),
    )
    deploy_id = get_deploy_id(one.vm.info(instance_id))
    if not deploy_id:
        raise RuntimeError("OpenNebula VM has no NICo DEPLOY_ID")
    instance = NicoAPI(api_timeout).get_instance(deploy_id)
    if str(instance.get("status") or "") != "Ready":
        raise RuntimeError(f"NICo instance is {instance.get('status')}, expected Ready")
    host = instance_ip(instance)
    if not host:
        raise RuntimeError("NICo instance has no interface IP")
    return deploy_id, host


def ssh_run(host: str, command: str, timeout: int) -> tuple[int, str, str]:
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
        command,
    ]
    result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def ensure_docker(host: str) -> None:
    """Install and start Docker if the guest image does not include it."""
    exit_code, _stdout, _stderr = ssh_run(host, "command -v docker >/dev/null 2>&1", 30)
    if exit_code == 0:
        return

    install_cmd = (
        "sudo apt-get update && "
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io && "
        "(sudo systemctl enable --now docker || sudo service docker start)"
    )
    exit_code, stdout, stderr = ssh_run(host, install_cmd, 600)
    if exit_code != 0:
        raise RuntimeError(f"Docker installation failed: {stderr.strip() or stdout.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy NIM container on OpenNebula BM instance")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--model", default="meta/llama-3.2-1b-instruct", help="NIM model name")
    parser.add_argument("--tag", default="latest", help="Container image tag")
    parser.add_argument("--port", type=int, default=8000, help="Host port to expose NIM on")
    parser.add_argument("--container-name", default="isv-nim", help="Docker container name")
    parser.add_argument("--timeout", type=int, default=600, help="Seconds to wait for NIM health endpoint")
    parser.add_argument("--api-timeout", type=int, default=60, help="NICo API request timeout")
    args = parser.parse_args()

    image = f"nvcr.io/nim/{args.model}:{args.tag}"
    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "skipped": False,
        "instance_id": str(args.instance_id),
        "container_name": args.container_name,
        "model": args.model,
        "image": image,
        "endpoint": f"http://localhost:{args.port}",
        "port": args.port,
        "health_ready": False,
        "ssh_user": "ubuntu",
    }

    ngc_api_key = os.environ.get("NGC_API_KEY", "") or os.environ.get("NGC_NIM_API_KEY", "")
    if not ngc_api_key:
        result.update({"success": True, "skipped": True, "skip_reason": "NGC_API_KEY not set"})
        print(json.dumps(result, indent=2))
        return 0

    try:
        deploy_id, host = resolve_instance(args.instance_id, args.api_timeout)
        result.update({"deploy_id": deploy_id, "nico_instance_id": deploy_id, "host": host, "public_ip": host, "private_ip": host})

        ensure_docker(host)

        exit_code, _stdout, stderr = ssh_run(
            host,
            f"echo {shlex.quote(ngc_api_key)} | sudo docker login nvcr.io -u '$oauthtoken' --password-stdin",
            120,
        )
        if exit_code != 0:
            raise RuntimeError(f"NGC login failed: {stderr.strip()}")

        ssh_run(host, f"sudo docker rm -f {shlex.quote(args.container_name)} 2>/dev/null || true", 120)
        ssh_run(host, "sudo docker system prune -af 2>/dev/null || true", 300)

        docker_cmd = (
            "sudo docker run -d --gpus all "
            f"--name {shlex.quote(args.container_name)} "
            f"-p {args.port}:8000 "
            f"-e NGC_API_KEY={shlex.quote(ngc_api_key)} "
            f"{shlex.quote(image)}"
        )
        exit_code, stdout, stderr = ssh_run(host, docker_cmd, 1200)
        if exit_code != 0:
            raise RuntimeError(f"docker run failed: {stderr.strip() or stdout.strip()}")
        result["container_id"] = stdout.strip()[:12]

        deadline = time.time() + args.timeout
        while time.time() < deadline:
            exit_code, stdout, _stderr = ssh_run(
                host,
                f"curl -sf http://localhost:{args.port}/v1/health/ready 2>/dev/null && echo OK || echo WAIT",
                30,
            )
            if exit_code == 0 and "OK" in stdout:
                result["health_ready"] = True
                break
            exit_code, stdout, _stderr = ssh_run(
                host,
                f"sudo docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(args.container_name)} 2>/dev/null",
                30,
            )
            if stdout.strip() != "true":
                _exit_code, logs, _stderr = ssh_run(
                    host,
                    f"sudo docker logs --tail 30 {shlex.quote(args.container_name)} 2>&1",
                    60,
                )
                raise RuntimeError(f"Container exited unexpectedly. Logs:\n{logs}")
            time.sleep(10)

        if not result["health_ready"]:
            _exit_code, logs, _stderr = ssh_run(
                host,
                f"sudo docker logs --tail 30 {shlex.quote(args.container_name)} 2>&1",
                60,
            )
            raise RuntimeError(f"Health endpoint not ready after {args.timeout}s. Logs:\n{logs}")

        result["success"] = True
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
