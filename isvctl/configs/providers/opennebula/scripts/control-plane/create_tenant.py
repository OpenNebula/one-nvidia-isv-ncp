#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Create an OpenNebula group for tenant lifecycle testing."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import allocate_group, get_one_server  # noqa: E402


def main() -> int:
    """Create an OpenNebula group and emit the tenant validation contract."""
    parser = argparse.ArgumentParser(description="Create OpenNebula tenant group")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula admin auth token")
    parser.add_argument("--name-prefix", default="isv-tenant-test")
    args = parser.parse_args()

    tenant_name = f"{args.name_prefix}-{uuid.uuid4().hex[:8]}"
    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "region": args.region,
        "tenant_name": tenant_name,
    }

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        tenant_id = allocate_group(one, tenant_name)
        result.update({"success": True, "tenant_id": tenant_id, "description": "OpenNebula group tenant"})
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
