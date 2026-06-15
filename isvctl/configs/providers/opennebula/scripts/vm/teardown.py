#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Teardown OpenNebula VM."""

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
    parser = argparse.ArgumentParser(description="Teardown OpenNebula instance")
    parser.add_argument("--instance-id", type=int, required=True, help="Instance ID")
    parser.add_argument("--skip-destroy", action="store_true", help="Skip termination block")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")
    
    result = {
        "success": False,
        "platform": "vm",
        "instance_id": str(args.instance_id),
    }

    if args.skip_destroy:
        print(f"Skipping destruction of {args.instance_id}", file=sys.stderr)
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        
        # Terminate Hard
        one.vm.action("terminate-hard", args.instance_id)

        result["state"] = "terminated"
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
