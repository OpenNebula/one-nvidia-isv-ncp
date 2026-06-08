#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Create or update the OpenNebula VM template used by the NICo driver."""

import argparse
import json
import os
import sys
import uuid
from typing import Any

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


def get_value(item: Any, key: str, default: Any = None) -> Any:
    """Return a value from a dict-like or attribute-based pyone object."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def quote(value: str) -> str:
    """Quote a scalar value for an OpenNebula template."""
    return json.dumps(str(value))


def env_value(name: str) -> str:
    """Return a required environment value or raise a clear error."""
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value


def build_template(args: argparse.Namespace) -> str:
    """Build the NICo VM template body described by the driver documentation."""
    lines = [
        f"NAME = {quote(args.name)}",
        "CPU = 1",
        "MEMORY = 1",
        f"NICO_INSTANCE_TYPE_ID = {quote(args.instance_type_id)}",
        f"NICO_OS_ID = {quote(args.os_id)}",
        f"NICO_SSH_KEY_GROUP_IDS = {quote(args.ssh_key_group_ids)}",
        f"NICO_VPC_ID = {quote(args.vpc_id)}",
        "NIC = [",
        f"  NICO_VPC_PREFIX_ID = {quote(args.vpc_prefix_id)}",
        "]",
        f"SCHED_REQUIREMENTS = {quote(args.sched_requirements)}",
    ]

    return "\n".join(lines)


def main() -> int:
    """Create or update a NICo VM template and emit its ID."""
    parser = argparse.ArgumentParser(description="Prepare OpenNebula NICo VM template")
    parser.add_argument("--name", default="isv-bm-nico-template", help="VM template name prefix")
    args = parser.parse_args()
    args.name = f"{args.name}-{uuid.uuid4().hex[:8]}"
    args.instance_type_id = env_value("ONE_BM_NICO_INSTANCE_TYPE_ID")
    args.os_id = env_value("ONE_BM_NICO_OS_ID")
    args.ssh_key_group_ids = env_value("ONE_BM_NICO_SSH_KEY_GROUP_IDS")
    args.vpc_id = env_value("ONE_BM_NICO_VPC_ID")
    args.vpc_prefix_id = env_value("ONE_BM_NICO_VPC_PREFIX_ID")
    args.sched_requirements = env_value("ONE_BM_NICO_SCHED_REQUIREMENTS")

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "template_name": args.name,
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        template_body = build_template(args)
        template_id = int(one.template.allocate(template_body))

        result["template_id"] = str(template_id)
        result["instance_type_id"] = args.instance_type_id
        result["vpc_id"] = args.vpc_id
        result["vpc_prefix_id"] = args.vpc_prefix_id
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
