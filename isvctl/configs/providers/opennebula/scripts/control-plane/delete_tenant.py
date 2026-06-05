#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Delete an OpenNebula tenant group."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import delete_group, find_group_by_name, get_one_server, get_value  # noqa: E402


def main() -> int:
    """Delete the OpenNebula group associated with a tenant lifecycle test."""
    parser = argparse.ArgumentParser(description="Delete OpenNebula tenant group")
    parser.add_argument("--group-name", required=True)
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula admin auth token")
    parser.add_argument("--skip-destroy", action="store_true")
    args = parser.parse_args()

    result: dict[str, Any] = {"success": False, "platform": "control_plane", "region": args.region}

    if args.skip_destroy:
        result.update({"success": True, "skipped": True})
        print(json.dumps(result, indent=2))
        return 0

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        group = find_group_by_name(one, args.group_name)
        if group is None:
            result.update({"success": True, "already_deleted": True})
        else:
            delete_group(one, str(get_value(group, "ID")))
            result.update({"success": True, "deleted_group": args.group_name})
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
