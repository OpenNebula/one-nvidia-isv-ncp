#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Get OpenNebula group information for tenant lifecycle testing."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import find_group_by_name, get_one_server, get_value  # noqa: E402


def main() -> int:
    """Get a tenant group and emit the tenant-info validation contract."""
    parser = argparse.ArgumentParser(description="Get OpenNebula tenant group")
    parser.add_argument("--group-name", required=True)
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula admin auth token")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "region": args.region,
        "tenant_name": args.group_name,
    }

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        group = find_group_by_name(one, args.group_name)
        if group is None:
            raise RuntimeError(f"Tenant {args.group_name} not found")
        result.update(
            {
                "success": True,
                "tenant_id": str(get_value(group, "ID", "")),
                "description": "OpenNebula group tenant",
            }
        )
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
