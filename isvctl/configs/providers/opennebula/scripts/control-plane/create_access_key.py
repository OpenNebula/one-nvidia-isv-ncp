#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Create an OpenNebula user credential for access-key lifecycle testing."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import allocate_user, get_one_server  # noqa: E402


def main() -> int:
    """Create an OpenNebula user and emit the access-key validation contract."""
    parser = argparse.ArgumentParser(description="Create OpenNebula access-key test user")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula admin auth token")
    parser.add_argument("--username-prefix", default="isv-access-key-test")
    parser.add_argument("--auth-driver", default="core")
    args = parser.parse_args()

    username = f"{args.username_prefix}-{uuid.uuid4().hex[:8]}"
    password = secrets.token_urlsafe(32)
    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "region": args.region,
        "username": username,
    }

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        user_id = allocate_user(one, username, password, args.auth_driver)
        result.update(
            {
                "success": True,
                "user_id": user_id,
                "access_key_id": username,
                "secret_access_key": password,
            }
        )
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
