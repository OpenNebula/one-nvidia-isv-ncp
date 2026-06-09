#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Verify the OpenNebula/NICo bare-metal configuration can provision instances."""

import argparse
import json
import os
import sys
from typing import Any

from describe_instance import get_value

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


REQUIRED_NICO_ENV = (
    "ONE_BM_NICO_CARBIDE_PROXY",
    "ONE_BM_NICO_SSA_ISSUER",
    "ONE_BM_NICO_NGC_ORG",
    "ONE_BM_NICO_ISV_CLIENT_ID",
    "ONE_BM_NICO_ISV_CLIENT_SECRET",
    "ONE_BM_NICO_TARGET_SCOPES",
)


def object_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify OpenNebula BM NICo config")
    parser.add_argument("--template-id", type=int, required=True, help="OpenNebula VM template ID")
    parser.add_argument("--host-id", type=int, required=True, help="OpenNebula host ID")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "config_id": str(args.template_id),
        "host_id": str(args.host_id),
        "dry_run_passed": False,
        "tests": {},
    }

    try:
        one = pyone.OneServer(
            os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"),
            session=os.environ.get("ONE_AUTH", "oneadmin:opennebula"),
        )
        template = one.template.info(args.template_id)
        host = one.host.info(args.host_id)
        template_body = object_dict(get_value(template, "TEMPLATE", {}))
        host_template = object_dict(get_value(host, "TEMPLATE", {}))

        config_name = str(get_value(template, "NAME", args.template_id))
        result["config_name"] = config_name

        nico_user_data = str(template_body.get("NICO_USER_DATA") or "")
        missing_env = [name for name in REQUIRED_NICO_ENV if not os.environ.get(name)]
        nico_host_attrs = [key for key in host_template if str(key).startswith("NICO_")]
        required_template_attrs = ("NICO_INSTANCE_TYPE_ID", "NICO_OS_ID", "NICO_VPC_ID", "NICO_USER_DATA")
        missing_template_attrs = [name for name in required_template_attrs if not template_body.get(name)]

        result["tests"] = {
            "template_exists": {"passed": True, "message": f"Template {args.template_id} exists"},
            "host_exists": {"passed": True, "message": f"Host {args.host_id} exists"},
            "nico_template_attrs": {
                "passed": not missing_template_attrs,
                "message": "Required NICo template attrs present" if not missing_template_attrs else f"Missing: {', '.join(missing_template_attrs)}",
            },
            "nico_user_data": {"passed": bool(nico_user_data), "message": "NICO_USER_DATA present"},
            "nico_env": {"passed": not missing_env, "message": "Required NICo env vars present" if not missing_env else f"Missing: {', '.join(missing_env)}"},
            "nico_host_attrs": {"passed": bool(nico_host_attrs), "message": f"Found {len(nico_host_attrs)} NICo host attrs"},
        }
        result["dry_run_passed"] = all(test["passed"] for test in result["tests"].values())
        result["success"] = result["dry_run_passed"]
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
