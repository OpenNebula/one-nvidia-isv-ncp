#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Verify OpenNebula NICo bare-metal resources were removed."""

import argparse
import json
import os
import sys
import time
from collections.abc import Callable
from typing import Any

try:
    import pyone
except ImportError:
    pyone = None


def is_missing(error: Exception) -> bool:
    """Return whether a pyone lookup error means the resource is absent."""
    message = str(error).lower()
    return (
        "does not exist" in message
        or "not found" in message
        or "error getting virtual machine" in message
        or "error getting virtual machine template" in message
        or "error getting host" in message
    )


def wait_until_missing(check: Callable[[], Any], timeout: int, *, done_state_ok: bool = False) -> bool:
    """Poll until a resource lookup fails as missing."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            resource = check()
            if done_state_ok and int(getattr(resource, "STATE", -1)) == 6:
                return True
        except Exception as e:
            if is_missing(e):
                return True
            raise

        time.sleep(5)

    return False


def using_existing_instance() -> bool:
    """Return whether the run targets a user-provided existing VM."""
    return bool(os.environ.get("ONE_BM_EXISTING_INSTANCE_ID", "").strip())


def main() -> int:
    """Verify VM, template, and host resources are absent."""
    parser = argparse.ArgumentParser(description="Verify OpenNebula bare-metal teardown")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--template-id", type=int, required=True, help="OpenNebula VM template ID")
    parser.add_argument("--host-id", type=int, required=True, help="OpenNebula host ID")
    parser.add_argument("--timeout", type=int, default=300, help="Seconds to wait for deletion")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "instance_id": str(args.instance_id),
        "template_id": str(args.template_id),
        "host_id": str(args.host_id),
        "tests": {},
    }

    if using_existing_instance():
        result["success"] = True
        result["skipped"] = True
        result["message"] = "Skipping teardown verification for ONE_BM_EXISTING_INSTANCE_ID"
        result["tests"] = {
            "instance_deleted": {
                "passed": True,
                "message": "skipped for existing instance",
            },
            "template_deleted": {
                "passed": True,
                "message": "skipped for existing instance",
            },
            "host_deleted": {
                "passed": True,
                "message": "skipped for existing instance",
            },
        }
        print(json.dumps(result, indent=2))
        return 0

    if pyone is None:
        print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
        return 1

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        checks = {
            "instance_deleted": (lambda: one.vm.info(args.instance_id), True),
            "template_deleted": (lambda: one.template.info(args.template_id), False),
            "host_deleted": (lambda: one.host.info(args.host_id), False),
        }

        for name, (check, done_state_ok) in checks.items():
            passed = wait_until_missing(check, args.timeout, done_state_ok=done_state_ok)
            result["tests"][name] = {
                "passed": passed,
                "message": "resource deleted" if passed else "resource still exists",
            }

        result["success"] = all(test["passed"] for test in result["tests"].values())
        if not result["success"]:
            result["error"] = "One or more resources still exist after teardown"

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
