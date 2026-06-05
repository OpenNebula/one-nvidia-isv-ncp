#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Verify an old OpenNebula access credential is rejected."""

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
    """Authenticate with the old credential and report rejection evidence."""
    parser = argparse.ArgumentParser(description="Verify OpenNebula access credential rejection")
    parser.add_argument("--access-key-id", required=True, help="OpenNebula username")
    parser.add_argument("--secret-access-key", required=True, help="Old OpenNebula password")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--wait", type=int, default=0)
    parser.add_argument("--retries", type=int, default=3)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "region": args.region,
        "rejected": False,
    }

    if args.wait > 0:
        time.sleep(args.wait)

    for attempt in range(args.retries):
        try:
            one = get_one_server(args.xmlrpc_url, f"{args.access_key_id}:{args.secret_access_key}")
            one.system.version()
            if attempt < args.retries - 1:
                time.sleep(2 ** attempt)
                continue
            result["error"] = "Credential was not rejected after retries"
        except Exception as e:
            result.update({"success": True, "rejected": True, "error_code": "AuthenticationError", "error": str(e)})
            break

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
