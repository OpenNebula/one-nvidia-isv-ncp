#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Retrieve user-defined tags on an OpenNebula NICo bare-metal VM."""

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
    return {}


def user_template_tags(user_template: Any) -> dict[str, str]:
    """Convert OpenNebula USER_TEMPLATE tag keys to provider-neutral tags."""
    raw_tags = object_items(user_template)
    tags: dict[str, str] = {}
    for storage_key, output_key in CANONICAL_OUTPUT_KEYS.items():
        value = raw_tags.get(storage_key)
        if value is not None and not isinstance(value, dict | list | tuple):
            tags[output_key] = str(value)
    return tags


def main() -> int:
    """Describe provider-neutral VM tags."""
    parser = argparse.ArgumentParser(description="Describe OpenNebula bare-metal VM tags")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "instance_id": str(args.instance_id),
        "tags": {},
        "tag_count": 0,
    }

    try:
        import pyone

        one = pyone.OneServer(xmlrpc_url, session=auth)
        vm_info = one.vm.info(args.instance_id)
        tags = user_template_tags(get_value(vm_info, "USER_TEMPLATE", {}))

        result["tags"] = tags
        result["tag_count"] = len(tags)
        result["success"] = True

    except ImportError:
        result["error"] = "pyone is not installed. Install pyone to run OpenNebula provider scripts."
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
