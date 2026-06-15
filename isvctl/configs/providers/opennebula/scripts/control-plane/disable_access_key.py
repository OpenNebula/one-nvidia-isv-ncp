#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Disable an OpenNebula test access credential by rotating its password."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import change_user_password, find_user_by_name, get_one_server, get_value  # noqa: E402


def main() -> int:
    """Disable the access credential while preserving the validation contract."""
    parser = argparse.ArgumentParser(description="Disable OpenNebula access credential")
    parser.add_argument("--username", required=True)
    parser.add_argument("--access-key-id", required=True)
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula admin auth token")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "access_key_id": args.access_key_id,
    }

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        user = find_user_by_name(one, args.username)
        if user is None:
            raise RuntimeError(f"User {args.username} not found")
        user_id = str(get_value(user, "ID"))
        change_user_password(one, user_id, secrets.token_urlsafe(32))
        result.update({"success": True, "user_id": user_id, "status": "Inactive"})
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
