#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Launch OpenNebula VM for VM testing.

Usage:
    python launch_instance.py --name test-gpu --template-id 1

Output JSON:
{
    "success": true,
    "instance_id": "100",
    "public_ip": "10.0.0.5",
    "state": "running"
}
"""

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any

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
    parser = argparse.ArgumentParser(description="Launch OpenNebula instance")
    parser.add_argument("--name", default="isv-test-gpu", help="Instance name")
    parser.add_argument("--template-id", required=True, type=int, help="Template ID")
    parser.add_argument("--key-file", help="Path to SSH key file (if managed externally)")
    parser.add_argument("--ssh-user", default="root", help="SSH username (default: root)")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")
    
    result = {
        "success": False,
        "platform": "vm",
        "instance_id": None,
        "instance_type": str(args.template_id),
    }

    try:
        if args.key_file:
            result["key_file"] = args.key_file

        one = pyone.OneServer(xmlrpc_url, session=auth)
        
        # Deploy VM from template
        vm_id = one.template.instantiate(args.template_id, args.name)
        result["instance_id"] = str(vm_id)

        # Wait for RUNNING state
        # State 3 is ACTIVE, lcm_state 3 is RUNNING
        timeout = 600
        start_time = time.time()
        running = False

        while time.time() - start_time < timeout:
            vm_info = one.vm.info(vm_id)
            state = vm_info.STATE
            lcm_state = vm_info.LCM_STATE

            if state == 3 and lcm_state == 3:
                running = True
                result["state"] = "running"
                break
            elif state in [6, 7]:  # DONE or FAILED
                result["state"] = "failed"
                raise RuntimeError(f"VM entered failed state {state}/{lcm_state}")
            
            time.sleep(5)

        if not running:
            raise RuntimeError("Timeout waiting for VM to reach RUNNING state")

        # Get IP address - retry if not immediately available
        ip = None
        ip_timeout = 60  # Additional timeout for IP availability
        ip_start_time = time.time()
        
        # Helper to extract from a pyone-parsed dict
        def get_ip_from_nic(nic_entry):
            if isinstance(nic_entry, dict) and "IP" in nic_entry:
                return nic_entry["IP"]
            if hasattr(nic_entry, "IP"):
                return nic_entry.IP
            return None
        
        # Retry IP extraction until timeout or successful
        while not ip and (time.time() - ip_start_time < ip_timeout):
            vm_info = one.vm.info(vm_id)  # Refresh VM info
            template_info = vm_info.TEMPLATE if hasattr(vm_info, 'TEMPLATE') else {}
            
            # Check CONTEXT
            if "CONTEXT" in template_info:
                ctx = template_info["CONTEXT"]
                if isinstance(ctx, dict) and "ETH0_IP" in ctx:
                    ip = ctx["ETH0_IP"]
                elif hasattr(ctx, "ETH0_IP"):
                    ip = ctx.ETH0_IP
            
            # Check NIC if no IP yet
            if not ip and "NIC" in template_info:
                nic = template_info["NIC"]
                if isinstance(nic, list) and len(nic) > 0:
                    ip = get_ip_from_nic(nic[0])
                else:
                    ip = get_ip_from_nic(nic)
            
            if ip:
                break
            
            # Wait before retrying
            time.sleep(2)
        
        if ip:
            result["public_ip"] = str(ip)
            result["private_ip"] = str(ip)
            result["ssh_user"] = args.ssh_user
            
            # If we have SSH credentials, wait for SSH to be ready
            if args.key_file:
                ssh_ready = wait_for_ssh(str(ip), args.ssh_user, args.key_file)
                result["ssh_ready"] = ssh_ready
                if not ssh_ready:
                    raise RuntimeError("SSH not ready after VM startup")
        else:
            # Log available information for debugging
            template_info = vm_info.TEMPLATE if hasattr(vm_info, 'TEMPLATE') else {}
            result["debug_info"] = {
                "template_keys": list(template_info.keys()) if isinstance(template_info, dict) else "not-a-dict",
                "has_nic": "NIC" in template_info,
                "has_context": "CONTEXT" in template_info,
                "vm_state": f"{state}/{lcm_state}",
                "ip_retrieval_timeout": ip_timeout,
                "time_elapsed": time.time() - ip_start_time,
            }
            # Return error since IP is essential for subsequent SSH validations
            raise RuntimeError("Could not retrieve VM IP address after timeout")

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
