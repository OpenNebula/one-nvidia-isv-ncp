#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Stop OpenNebula VM."""

import argparse
import json
import os
import sys
import time

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Stop OpenNebula instance")
    parser.add_argument("--instance-id", type=int, required=True, help="Instance ID")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")
    
    result = {
        "success": False,
        "platform": "vm",
        "instance_id": str(args.instance_id),
        "stop_initiated": False,
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        
        # 8 = POWEROFF - powers off the VM
        one.vm.action("poweroff", args.instance_id)
        result["stop_initiated"] = True

        timeout = 300
        start_time = time.time()
        powered_off = False

        while time.time() - start_time < timeout:
            vm_info = one.vm.info(args.instance_id)
            # State 8 is POWEROFF
            if vm_info.STATE == 8:
                powered_off = True
                result["state"] = "stopped"  # Map to standard state
                break
            time.sleep(5)

        if not powered_off:
            raise RuntimeError("Timeout waiting for VM to power off")

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
