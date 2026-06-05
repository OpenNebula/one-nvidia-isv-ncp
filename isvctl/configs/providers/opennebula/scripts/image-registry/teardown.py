#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Tear down OpenNebula image-registry resources."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.image_registry import (  # noqa: E402
    get_one_server,
    image_exists,
    wait_for_image_deleted,
)


def main() -> int:
    """Delete OpenNebula image-registry resources and emit structured JSON output."""
    parser = argparse.ArgumentParser(description="Teardown OpenNebula image-registry resources")
    parser.add_argument("--image-id", default="", help="Imported OpenNebula image ID")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--skip-destroy", action="store_true", help="Skip deletion")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "image_registry",
        "resources_deleted": [],
        "resources_failed": [],
    }

    if args.skip_destroy:
        result["success"] = True
        result["message"] = "Image-registry teardown skipped"
        print(json.dumps(result, indent=2))
        return 0

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        if args.image_id and image_exists(one, args.image_id):
            one.image.delete(int(args.image_id))
            if wait_for_image_deleted(one, args.image_id):
                result["resources_deleted"].append(f"image:{args.image_id}")
            else:
                result["resources_failed"].append(f"image:{args.image_id}")
        result["success"] = not result["resources_failed"]
        result["message"] = "OpenNebula image-registry teardown complete"
    except Exception as e:
        result["error"] = str(e)
        if args.image_id:
            result["resources_failed"].append(f"image:{args.image_id}")

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
