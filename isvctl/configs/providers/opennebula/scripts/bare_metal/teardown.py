#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Teardown an OpenNebula NICo bare-metal VM."""

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


def as_bool(value: str | None) -> bool:
    """Parse a Jinja-rendered boolean string."""
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def wait_for_vm_terminated(one: object, instance_id: int, timeout: int = 600) -> bool:
    """Wait for a VM to reach DONE or disappear from the pool."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            vm_info = one.vm.info(instance_id)
            if int(getattr(vm_info, "STATE", -1)) == 6:
                return True
        except Exception as e:
            message = str(e).lower()
            if "does not exist" in message or "not found" in message:
                return True

        time.sleep(5)

    return False


def main() -> int:
    """Terminate the OpenNebula VM backing a NICo bare-metal instance."""
    parser = argparse.ArgumentParser(description="Teardown OpenNebula bare-metal instance")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--template-id", type=int, help="OpenNebula VM template ID to delete if created by this run")
    parser.add_argument("--host-id", type=int, help="OpenNebula host ID to delete if created by this run")
    parser.add_argument("--template-created", default="false", help="Whether the template was created by this run")
    parser.add_argument("--host-created", default="false", help="Whether the host was created by this run")
    parser.add_argument("--skip-destroy", action="store_true", help="Skip VM termination")
    args = parser.parse_args()

    result: dict[str, object] = {
        "success": False,
        "platform": "bm",
        "instance_id": str(args.instance_id),
        "template_id": str(args.template_id) if args.template_id is not None else None,
        "host_id": str(args.host_id) if args.host_id is not None else None,
        "cleanup": {},
    }

    if args.skip_destroy:
        result["success"] = True
        result["skipped"] = True
        result["state"] = "running"
        print(json.dumps(result, indent=2))
        return 0

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        one.vm.action("terminate-hard", args.instance_id)
        wait_for_vm_terminated(one, args.instance_id)

        result["state"] = "terminated"

        cleanup = result["cleanup"]
        if as_bool(args.template_created) and args.template_id is not None:
            try:
                one.template.delete(args.template_id)
                cleanup["template"] = "deleted"
            except Exception as e:
                cleanup["template"] = f"failed: {e}"

        if as_bool(args.host_created) and args.host_id is not None:
            try:
                one.host.delete(args.host_id)
                cleanup["host"] = "deleted"
            except Exception as e:
                cleanup["host"] = f"failed: {e}"

        result["success"] = True
    except Exception as e:
        message = str(e)
        if "does not exist" in message or "not found" in message.lower():
            result["state"] = "terminated"
            result["success"] = True
            result["already_deleted"] = True
        else:
            result["error"] = message

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
