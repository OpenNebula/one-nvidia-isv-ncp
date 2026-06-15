#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Authenticate to OpenNebula with a test access credential."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import get_one_server  # noqa: E402


def main() -> int:
    """Verify the generated OpenNebula user credential can authenticate."""
    parser = argparse.ArgumentParser(description="Test OpenNebula access credential")
    parser.add_argument("--access-key-id", required=True, help="OpenNebula username")
    parser.add_argument("--secret-access-key", required=True, help="OpenNebula password")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--wait", type=int, default=0)
    parser.add_argument("--retries", type=int, default=3)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "region": args.region,
        "authenticated": False,
    }

    if args.wait > 0:
        time.sleep(args.wait)

    last_error = ""
    for attempt in range(args.retries):
        try:
            one = get_one_server(args.xmlrpc_url, f"{args.access_key_id}:{args.secret_access_key}")
            version = one.system.version()
            result.update(
                {
                    "success": True,
                    "authenticated": True,
                    "identity_id": args.access_key_id,
                    "account_id": args.access_key_id,
                    "api_version": str(version),
                }
            )
            break
        except Exception as e:
            last_error = str(e)
            if attempt < args.retries - 1:
                time.sleep(2 ** attempt)

    if not result["success"]:
        result["error"] = last_error

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
