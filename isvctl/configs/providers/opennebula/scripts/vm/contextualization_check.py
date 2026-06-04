#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula VM contextualization from inside the guest.

OpenNebula does not require EC2-style cloud-init metadata. The equivalent
contract is that the VM receives a resolved CONTEXT payload and one-context
applies it in the guest.

Usage:
    python contextualization_check.py --instance-id 241 \
        --public-ip 172.20.0.10 --key-file /tmp/one_vm_key
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
from typing import Any

CONTEXT_PATHS = (
    "/run/one-context/one_env",
    "/var/run/one-context/one_env",
    "/var/lib/one-context/one_env",
    "/mnt/context.sh",
    "/media/context.sh",
)

DEFAULT_REQUIRED_KEYS = (
    "SSH_PUBLIC_KEY",
    "ETH0_IP",
    "VMID",
    "ONEGATE_ENDPOINT",
    "TOKENTXT",
)


def ssh_run(
    host: str,
    user: str,
    key_file: str,
    command: str,
    timeout: int = 30,
    connect_timeout: int = 10,
) -> tuple[int, str, str]:
    """Run a command over SSH and return exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                f"ConnectTimeout={connect_timeout}",
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


def _compact(text: str, max_length: int = 240) -> str:
    """Collapse whitespace and cap length for one-line diagnostics."""
    compact = " ".join(text.split())
    if len(compact) <= max_length:
        return compact
    return f"{compact[: max_length - 3]}..."


def validate_required_keys(keys: list[str]) -> list[str]:
    """Validate requested context keys are safe shell variable names."""
    invalid = [key for key in keys if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)]
    if invalid:
        raise ValueError(f"Invalid context key name(s): {', '.join(invalid)}")
    return keys


def find_context_file(host: str, user: str, key_file: str, timeout: int) -> tuple[str | None, str | None]:
    """Return the first readable OpenNebula context file path in the guest."""
    path_args = " ".join(shlex.quote(path) for path in CONTEXT_PATHS)
    command = (
        f"for path in {path_args}; do "
        'if [ -r "$path" ]; then printf "%s" "$path"; exit 0; fi; '
        "done; exit 1"
    )
    exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=timeout)
    if exit_code != 0:
        return None, _compact(stderr or stdout or "no readable OpenNebula context file found")
    return stdout.strip().splitlines()[0] if stdout.strip() else None, None


def check_context_keys(
    host: str,
    user: str,
    key_file: str,
    context_file: str,
    required_keys: list[str],
    timeout: int,
) -> tuple[list[str], list[str], str | None]:
    """Return present and missing required keys from a guest context file."""
    if not required_keys:
        return [], [], None

    key_args = " ".join(shlex.quote(key) for key in required_keys)
    command = (
        f"context_file={shlex.quote(context_file)}; "
        'present=""; missing=""; '
        f"for key in {key_args}; do "
        'if grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=" "$context_file"; '
        'then present="$present $key"; '
        'else missing="$missing $key"; fi; '
        "done; "
        'echo "present:${present# }"; '
        'if [ -n "$missing" ]; then echo "missing:${missing# }"; exit 1; fi'
    )
    exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=timeout)
    present: list[str] = []
    missing: list[str] = []
    for line in stdout.splitlines():
        if line.startswith("present:"):
            present = [key for key in line.removeprefix("present:").split() if key]
        elif line.startswith("missing:"):
            missing = [key for key in line.removeprefix("missing:").split() if key]
    if exit_code != 0:
        return present, missing, _compact(stderr or stdout or "required context keys missing")
    return present, missing, None


def check_one_context_service(
    host: str,
    user: str,
    key_file: str,
    timeout: int,
) -> tuple[bool, str]:
    """Return whether one-context service evidence is acceptable."""
    command = (
        "if command -v systemctl >/dev/null 2>&1 "
        "&& systemctl list-unit-files one-context.service >/dev/null 2>&1; then "
        "state=$(systemctl show one-context.service -p ActiveState --value 2>/dev/null || true); "
        "result=$(systemctl show one-context.service -p Result --value 2>/dev/null || true); "
        "status=$(systemctl show one-context.service -p ExecMainStatus --value 2>/dev/null || true); "
        'echo "state=$state result=$result status=$status"; '
        'if [ "$result" = "success" ] || [ "$status" = "0" ] || [ "$state" = "active" ]; then '
        "exit 0; else exit 1; fi; "
        "else echo 'one-context.service not present; context file evidence used'; exit 0; fi"
    )
    exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=timeout)
    return exit_code == 0, _compact(stdout or stderr or "one-context service check returned no output")


def main() -> int:
    """Validate OpenNebula contextualization and emit structured JSON."""
    parser = argparse.ArgumentParser(description="Validate OpenNebula VM contextualization")
    parser.add_argument("--instance-id", required=True, help="OpenNebula VM ID")
    parser.add_argument("--public-ip", required=True, help="SSH host for guest probes")
    parser.add_argument("--key-file", required=True, help="SSH private key path")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument("--required-key", action="append", default=[], help="Required CONTEXT key")
    parser.add_argument("--ssh-timeout", type=int, default=60, help="Seconds for each SSH probe")
    args = parser.parse_args()

    required_keys = validate_required_keys(args.required_key or list(DEFAULT_REQUIRED_KEYS))
    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "test_name": "opennebula_contextualization",
        "instance_id": str(args.instance_id),
        "contextualization_completed": False,
        "context_source_found": False,
        "required_context_keys_present": False,
        "context_keys_present": [],
        "context_keys_missing": required_keys,
    }

    try:
        context_file, error = find_context_file(args.public_ip, args.ssh_user, args.key_file, args.ssh_timeout)
        if error or not context_file:
            result["error"] = error or "no readable OpenNebula context file found"
            print(json.dumps(result, indent=2))
            return 1

        result["context_source"] = context_file
        result["context_source_found"] = True

        present, missing, error = check_context_keys(
            args.public_ip,
            args.ssh_user,
            args.key_file,
            context_file,
            required_keys,
            args.ssh_timeout,
        )
        result["context_keys_present"] = present
        result["context_keys_missing"] = missing
        result["required_context_keys_present"] = not missing
        if error:
            result["error"] = error
            print(json.dumps(result, indent=2))
            return 1

        service_ok, service_message = check_one_context_service(
            args.public_ip,
            args.ssh_user,
            args.key_file,
            args.ssh_timeout,
        )
        result["one_context_service_ok"] = service_ok
        result["one_context_service"] = service_message
        if not service_ok:
            result["error"] = service_message
            print(json.dumps(result, indent=2))
            return 1

        result["contextualization_completed"] = True
        result["success"] = True
        result["message"] = f"OpenNebula contextualization verified using {context_file}"

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
