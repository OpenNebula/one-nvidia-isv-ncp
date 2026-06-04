#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Create or update the OpenNebula Host used by the NICo drivers."""

import argparse
import json
import os
import sys
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


def as_list(value: Any) -> list[Any]:
    """Normalize a pyone scalar-or-list value to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def find_host(one: Any, name: str) -> Any | None:
    """Find an OpenNebula host by name."""
    pool = one.hostpool.info()
    for host in as_list(get_value(pool, "HOST")):
        if str(get_value(host, "NAME", "")) == name:
            return host
    return None


def env_value(name: str) -> str:
    """Return a required environment value or raise a clear error."""
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value


def main() -> int:
    """Create or update a NICo host and emit its ID."""
    parser = argparse.ArgumentParser(description="Prepare OpenNebula NICo host")
    parser.add_argument("--name", default="nico", help="OpenNebula host name")
    args = parser.parse_args()

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "host_name": args.name,
        "created": False,
        "updated": False,
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        host = find_host(one, args.name)

        if host is None:
            host_id = int(one.host.allocate(args.name, "nico", "nico", 0))
            result["created"] = True
        else:
            host_id = int(get_value(host, "ID"))

        attrs = {
            "NICO_CARBIDE_PROXY": env_value("ONE_BM_NICO_CARBIDE_PROXY"),
            "NICO_SSA_ISSUER": env_value("ONE_BM_NICO_SSA_ISSUER"),
            "NICO_NGC_ORG": env_value("ONE_BM_NICO_NGC_ORG"),
            "NICO_ISV_CLIENT_ID": env_value("ONE_BM_NICO_ISV_CLIENT_ID"),
            "NICO_ISV_CLIENT_SECRET": env_value("ONE_BM_NICO_ISV_CLIENT_SECRET"),
            "NICO_TARGET_SCOPES": env_value("ONE_BM_NICO_TARGET_SCOPES"),
            "NICO_ALLOCATION": env_value("ONE_BM_NICO_ALLOCATION"),
        }

        current = get_value(one.host.info(host_id), "TEMPLATE", {})
        merged = dict(current) if isinstance(current, dict) else {}
        merged.update(attrs)
        one.host.update(host_id, merged, 1)

        result["host_id"] = str(host_id)
        result["updated"] = True
        result["attributes"] = sorted(attrs.keys())
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
