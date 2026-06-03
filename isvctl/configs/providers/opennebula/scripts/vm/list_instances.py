#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""List OpenNebula VMs."""

import argparse
import json
import os
import sys

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="List OpenNebula instances")
    parser.add_argument("--instance-id", type=int, required=True, help="Instance ID")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")
    
    result = {
        "success": False,
        "platform": "vm",
        "instances": [],
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        
        vm_info = one.vm.info(args.instance_id)
        if vm_info:
            # Map OpenNebula state to standard state
            state_map = {
                0: "init",
                1: "pending",
                2: "hold",
                3: "active",
                4: "stopped",
                5: "suspended",
                6: "done",
                7: "failed",
                8: "powered_off",
            }
            state = state_map.get(vm_info.STATE, "unknown")
            
            instance = {
                "instance_id": str(args.instance_id),
                "state": state,
                "vpc_id": "opennebula",  # OpenNebula doesn't have VPC concept
            }
            
            # Try to get IP addresses and network info
            if hasattr(vm_info, 'TEMPLATE') and vm_info.TEMPLATE:
                template = vm_info.TEMPLATE
                if hasattr(template, 'NIC') and template.NIC:
                    nic = template.NIC[0] if isinstance(template.NIC, list) else template.NIC
                    if hasattr(nic, 'IP'):
                        instance["private_ip"] = nic.IP
                    # Get Virtual Network ID
                    if hasattr(nic, 'NETWORK_ID'):
                        instance["network_id"] = str(nic.NETWORK_ID)
                    elif hasattr(nic, 'NETWORK'):
                        instance["network_id"] = str(nic.NETWORK)
            
            result["instances"].append(instance)
            result["count"] = len(result["instances"])
            result["found_target"] = True
            result["target_instance"] = str(args.instance_id)
            result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
