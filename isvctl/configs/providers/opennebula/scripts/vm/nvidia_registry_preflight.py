#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Prepare remote Docker access to NVIDIA registry for OpenNebula VM tests."""

import argparse
import json
import os
import shlex
import sys
from typing import Any

import paramiko

DEFAULT_CUDA_PROBE_IMAGE = "nvcr.io/nvidia/cuda:13.0.0-base-ubuntu24.04"


def ssh_connect(host: str, user: str, key_file: str) -> paramiko.SSHClient:
    """Create SSH connection to the remote VM."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=user,
        key_filename=key_file,
        timeout=30,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def run_cmd(ssh: paramiko.SSHClient, command: str, timeout: int = 120) -> tuple[int, str, str]:
    """Execute a remote command over SSH."""
    _, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, stdout.read().decode(), stderr.read().decode()


def main() -> int:
    """Log in to NGC if credentials are present and check the CUDA probe tag."""
    parser = argparse.ArgumentParser(description="OpenNebula NVIDIA registry preflight")
    parser.add_argument("--host", required=True, help="Remote VM IP or hostname")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--user", default="root", help="SSH username")
    parser.add_argument("--image", default=DEFAULT_CUDA_PROBE_IMAGE, help="Container image tag to check")
    parser.add_argument(
        "--ngc-api-key",
        default=os.environ.get("NGC_API_KEY", "") or os.environ.get("NGC_NIM_API_KEY", ""),
        help="NGC API key used for docker login",
    )
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "test_name": "nvidia_registry_preflight",
        "image": args.image,
        "login_performed": False,
        "login_skipped": False,
        "tag_exists": False,
    }

    ssh = None
    try:
        ssh = ssh_connect(args.host, args.user, args.key_file)

        exit_code, stdout, stderr = run_cmd(ssh, "docker --version")
        if exit_code != 0:
            result["error"] = f"Docker is not available: {(stderr or stdout).strip()}"
            print(json.dumps(result, indent=2))
            return 1

        if args.ngc_api_key:
            safe_key = shlex.quote(args.ngc_api_key)
            login_cmd = f"printf %s {safe_key} | docker login nvcr.io -u '$oauthtoken' --password-stdin"
            exit_code, stdout, stderr = run_cmd(ssh, login_cmd)
            if exit_code != 0:
                result["error"] = f"NGC docker login failed: {(stderr or stdout).strip()}"
                print(json.dumps(result, indent=2))
                return 1
            result["login_performed"] = True
        else:
            result["login_skipped"] = True

        image_ref = shlex.quote(args.image)
        exit_code, stdout, stderr = run_cmd(ssh, f"docker manifest inspect {image_ref} >/dev/null")
        if exit_code != 0:
            result["error"] = f"Container image tag not found or not accessible: {(stderr or stdout).strip()}"
            print(json.dumps(result, indent=2))
            return 1

        result["tag_exists"] = True
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)
    finally:
        if ssh:
            ssh.close()

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
