#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""List OpenNebula groups as tenants."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import get_one_server, get_value, list_groups  # noqa: E402


def main() -> int:
    """List OpenNebula tenant groups and optionally verify a target exists."""
    parser = argparse.ArgumentParser(description="List OpenNebula tenant groups")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula admin auth token")
    parser.add_argument("--group-name", help="Tenant group name to verify")
    args = parser.parse_args()

    result: dict[str, Any] = {"success": False, "platform": "control_plane", "region": args.region, "tenants": []}

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        for group in list_groups(one):
            result["tenants"].append(
                {
                    "tenant_name": str(get_value(group, "NAME", "")),
                    "tenant_id": str(get_value(group, "ID", "")),
                }
            )

        if args.group_name:
            result["target_tenant"] = args.group_name
            result["found_target"] = any(t["tenant_name"] == args.group_name for t in result["tenants"])

        result["count"] = len(result["tenants"])
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
