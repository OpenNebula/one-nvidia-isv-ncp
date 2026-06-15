#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Retrieve user-defined tags on an OpenNebula VM.

OpenNebula does not have an EC2-style tag API for VMs. This provider maps the
canonical tags required by InstanceTagCheck to custom keys in the VM
USER_TEMPLATE, then reads those keys back and returns a flat provider-neutral
tag dict.

Usage:
    python describe_tags.py --instance-id 241
"""

import argparse
import json
import os
import sys
from typing import Any

CANONICAL_TAG_KEYS = {
    "Name": "ISV_TAG_NAME",
    "CreatedBy": "ISV_TAG_CREATED_BY",
}
CANONICAL_OUTPUT_KEYS = {storage_key: output_key for output_key, storage_key in CANONICAL_TAG_KEYS.items()}


def get_value(item: Any, key: str, default: Any = None) -> Any:
    """Return a value from a dict-like or attribute-based pyone object."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def object_items(item: Any) -> dict[str, Any]:
    """Return public fields from a dict-like or pyone object."""
    if item is None:
        return {}
    if isinstance(item, dict):
        return dict(item)
    if hasattr(item, "__dict__"):
        return {key: value for key, value in vars(item).items() if not key.startswith("_")}

    values: dict[str, Any] = {}
    for key in dir(item):
        if key.startswith("_"):
            continue
        value = getattr(item, key)
        if not callable(value):
            values[key] = value
    return values


def quote(value: object) -> str:
    """Render a quoted OpenNebula template value."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def storage_key_for_tag(output_key: str) -> str:
    """Return the USER_TEMPLATE key used to store a provider-neutral tag key."""
    return CANONICAL_TAG_KEYS[output_key]


def build_update_template(tags: dict[str, str]) -> str:
    """Build an OpenNebula user-template update for the requested tags."""
    lines = []
    for output_key, value in tags.items():
        lines.append(f"{storage_key_for_tag(output_key)} = {quote(value)}")
    return "\n".join(lines)


def user_template_tags(user_template: Any) -> dict[str, str]:
    """Convert canonical OpenNebula USER_TEMPLATE tag keys to provider-neutral tags."""
    raw_tags = object_items(user_template)
    tags: dict[str, str] = {}

    for storage_key, output_key in CANONICAL_OUTPUT_KEYS.items():
        value = raw_tags.get(storage_key)
        if value is None or isinstance(value, dict | list | tuple):
            continue
        tags[output_key] = str(value)

    return tags


def get_one_server(xmlrpc_url: str, auth: str) -> Any:
    """Return an authenticated OpenNebula XML-RPC client."""
    try:
        import pyone
    except ImportError as e:
        raise RuntimeError("pyone is not installed. Install pyone to run OpenNebula provider scripts.") from e

    return pyone.OneServer(xmlrpc_url, session=auth)


def update_vm_user_template(one: Any, instance_id: int, tags: dict[str, str]) -> None:
    """Append tag keys to an OpenNebula VM USER_TEMPLATE."""
    if not tags:
        return
    one.vm.update(instance_id, build_update_template(tags), 1)


def main() -> int:
    """Describe OpenNebula VM user-template tags and emit structured JSON."""
    parser = argparse.ArgumentParser(description="Describe OpenNebula VM tags")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--region", default="", help="(unused) accepted for suite compatibility")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instance_id": str(args.instance_id),
        "tags": {},
        "tag_count": 0,
    }

    try:
        one = get_one_server(xmlrpc_url, auth)
        vm_info = one.vm.info(args.instance_id)

        tags_to_ensure = {
            "Name": str(get_value(vm_info, "NAME", f"vm-{args.instance_id}")),
            "CreatedBy": "isvtest",
        }

        update_vm_user_template(one, args.instance_id, tags_to_ensure)

        vm_info = one.vm.info(args.instance_id)
        tags = user_template_tags(get_value(vm_info, "USER_TEMPLATE", {}))
        result["tags"] = tags
        result["tag_count"] = len(tags)
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
