#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Report topology placement evidence for an OpenNebula/NICo BM instance."""

import argparse
import json
import os
import sys

from describe_instance import NicoAPI, get_deploy_id, get_value, instance_ip

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate OpenNebula BM topology placement evidence")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--api-timeout", type=int, default=60, help="NICo API request timeout")
    args = parser.parse_args()

    result = {
        "success": False,
        "platform": "bm",
        "instance_id": str(args.instance_id),
        "placement_supported": False,
        "placement_strategy": "nico-allocation",
        "operations": {},
    }

    try:
        one = pyone.OneServer(
            os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"),
            session=os.environ.get("ONE_AUTH", "oneadmin:opennebula"),
        )
        vm_info = one.vm.info(args.instance_id)
        deploy_id = get_deploy_id(vm_info)
        if not deploy_id:
            raise RuntimeError("OpenNebula VM has no NICo DEPLOY_ID")
        instance = NicoAPI(args.api_timeout).get_instance(deploy_id)
        machine_id = str(instance.get("machineId") or get_value(vm_info, "MACHINE_ID", ""))
        status = str(instance.get("status") or "")
        ip = instance_ip(instance)

        result.update(
            {
                "deploy_id": deploy_id,
                "nico_instance_id": deploy_id,
                "machine_id": machine_id,
                "availability_zone": str(instance.get("location") or instance.get("zone") or "nico"),
                "placement_group": machine_id or deploy_id,
                "public_ip": ip,
                "private_ip": ip,
                "placement_supported": bool(machine_id and status == "Ready"),
                "operations": {
                    "opennebula_vm_lookup": {"passed": True, "message": f"VM {args.instance_id} found"},
                    "nico_instance_lookup": {"passed": True, "message": f"NICo instance {deploy_id} found"},
                    "nico_ready": {"passed": status == "Ready", "message": f"NICo status={status}"},
                    "machine_assignment": {"passed": bool(machine_id), "message": f"machine_id={machine_id or '<missing>'}"},
                },
            }
        )
        result["success"] = result["placement_supported"] and all(op["passed"] for op in result["operations"].values())
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
