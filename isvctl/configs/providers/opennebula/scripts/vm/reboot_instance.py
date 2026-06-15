#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Reboot OpenNebula VM."""

import argparse
import json
import os
import subprocess
import sys
import time

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


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


def get_uptime_via_ssh(host: str, user: str, key_file: str) -> float | None:
    """Get system uptime in seconds via SSH."""
    exit_code, stdout, _stderr = ssh_run(
        host,
        user,
        key_file,
        "cat /proc/uptime | cut -d' ' -f1",
    )
    if exit_code != 0:
        return None

    try:
        return float(stdout.strip())
    except ValueError:
        return None


def wait_for_reboot_confirmation(
    host: str,
    user: str,
    key_file: str,
    reboot_requested_at: float,
    pre_uptime: float | None,
    timeout: int = 300,
    interval: int = 5,
) -> tuple[bool, float | None]:
    """Poll SSH uptime until it proves the VM rebooted after the API request."""
    deadline = time.time() + timeout
    last_uptime = None

    while time.time() < deadline:
        uptime = get_uptime_via_ssh(host, user, key_file)
        if uptime is not None:
            last_uptime = uptime
            boot_started_at = time.time() - uptime
            if boot_started_at >= reboot_requested_at:
                return True, uptime
            if pre_uptime is not None and uptime < pre_uptime:
                return True, uptime

        time.sleep(interval)

    return False, last_uptime


def wait_for_ssh(
    host: str,
    user: str,
    key_file: str,
    max_attempts: int = 30,
    interval: int = 10,
) -> bool:
    """Wait for SSH to become available on the host.

    Args:
        host: Public IP or hostname
        user: SSH username
        key_file: Path to SSH private key
        max_attempts: Maximum number of connection attempts
        interval: Seconds between attempts

    Returns:
        True if SSH is ready, False if timed out
    """
    for attempt in range(1, max_attempts + 1):
        exit_code, _stdout, _stderr = ssh_run(host, user, key_file, "exit 0", timeout=15)
        if exit_code == 0:
            print(f"  SSH ready after attempt {attempt}", file=sys.stderr)
            return True

        if attempt < max_attempts:
            time.sleep(interval)

    print(f"  SSH not ready after {max_attempts} attempts", file=sys.stderr)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Reboot OpenNebula instance")
    parser.add_argument("--instance-id", type=int, required=True, help="Instance ID")
    parser.add_argument("--key-file", help="Path to SSH key file (if managed externally)")
    parser.add_argument("--public-ip", help="Public IP to pass-through")
    parser.add_argument("--ssh-user", default="root", help="SSH username (default: root)")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result = {
        "success": False,
        "platform": "vm",
        "instance_id": str(args.instance_id),
        "reboot_initiated": False,
        "ssh_ready": False,
        "reboot_confirmed": False,
    }

    try:
        if args.key_file:
            result["key_file"] = args.key_file
        if args.public_ip:
            result["public_ip"] = args.public_ip

        one = pyone.OneServer(xmlrpc_url, session=auth)

        pre_uptime = None
        if args.public_ip and args.key_file:
            pre_uptime = get_uptime_via_ssh(args.public_ip, args.ssh_user, args.key_file)
            if pre_uptime is not None:
                result["pre_reboot_uptime"] = round(pre_uptime, 1)
                print(f"  Pre-reboot uptime: {pre_uptime:.0f}s", file=sys.stderr)

        reboot_requested_at = time.time()
        one.vm.action("reboot", args.instance_id)
        result["reboot_initiated"] = True

        # Naive wait since reboot may not drop immediately to non-running status
        time.sleep(10)

        timeout = 300
        start_time = time.time()
        running = False

        while time.time() - start_time < timeout:
            vm_info = one.vm.info(args.instance_id)
            if vm_info.STATE == 3 and vm_info.LCM_STATE == 3:
                running = True
                result["state"] = "running"
                break
            time.sleep(5)

        if not running:
            raise RuntimeError("Timeout waiting for VM to finish reboot")

        # If we have SSH credentials, wait for SSH to be ready after reboot
        if args.public_ip and args.key_file:
            ssh_ready = wait_for_ssh(args.public_ip, args.ssh_user, args.key_file)
            result["ssh_ready"] = ssh_ready
            if not ssh_ready:
                raise RuntimeError("SSH not ready after VM reboot")
        else:
            raise RuntimeError("Missing public IP or key file; cannot affirm reboot via SSH")

        confirmed, post_uptime = wait_for_reboot_confirmation(
            args.public_ip,
            args.ssh_user,
            args.key_file,
            reboot_requested_at,
            pre_uptime,
        )
        if post_uptime is None:
            raise RuntimeError("Could not sample post-reboot uptime via SSH")

        result["uptime_seconds"] = round(post_uptime, 1)
        print(f"  Post-reboot uptime: {post_uptime:.0f}s", file=sys.stderr)

        if confirmed:
            result["reboot_confirmed"] = True
        else:
            raise RuntimeError("Reboot could not be confirmed from uptime evidence")

        result["ssh_user"] = args.ssh_user
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
