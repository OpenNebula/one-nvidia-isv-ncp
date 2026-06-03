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
                    "exit 0",
                ],
                capture_output=True,
                timeout=15,
            )
            if result.returncode == 0:
                print(f"  SSH ready after attempt {attempt}", file=sys.stderr)
                return True
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

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
    }

    try:
        if args.key_file:
            result["key_file"] = args.key_file
        if args.public_ip:
            result["public_ip"] = args.public_ip

        one = pyone.OneServer(xmlrpc_url, session=auth)
        
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

        result["ssh_user"] = args.ssh_user
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
