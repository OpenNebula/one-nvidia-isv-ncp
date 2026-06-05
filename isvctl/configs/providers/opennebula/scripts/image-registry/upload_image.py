#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Import a VM image into an OpenNebula image datastore."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.image_registry import (  # noqa: E402
    get_one_server,
    image_state_name,
    quote,
    wait_for_image_state,
)


def build_image_template(name: str, image_url: str, image_format: str, region: str) -> str:
    """Build an OpenNebula image template for an imported OS image."""
    return "\n".join(
        [
            f"NAME = {quote(name)}",
            "TYPE = OS",
            f"PATH = {quote(image_url)}",
            f"FORMAT = {quote(image_format)}",
            "DEV_PREFIX = vd",
            f'ISVTEST_REGION = {quote(region)}',
        ]
    )


def allocate_image(one: Any, template: str, datastore_id: int) -> str:
    """Allocate an OpenNebula image and return its ID."""
    try:
        return str(int(one.image.allocate(template, datastore_id)))
    except TypeError:
        return str(int(one.image.allocate(template)))


def main() -> int:
    """Import an OpenNebula image and emit structured JSON output."""
    parser = argparse.ArgumentParser(description="Import VM image into OpenNebula")
    parser.add_argument("--image-url", required=True, help="Image path or URL accepted by OpenNebula")
    parser.add_argument("--image-format", default="qcow2", help="Image format")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--datastore-id", required=True, type=int, help="OpenNebula image datastore ID")
    parser.add_argument("--name", default="", help="Optional OpenNebula image name")
    parser.add_argument("--wait-timeout", default=600, type=int, help="Seconds to wait for image readiness")
    args = parser.parse_args()

    image_name = args.name or f"isvtest-image-{uuid.uuid4().hex[:8]}"
    result: dict[str, Any] = {
        "success": False,
        "platform": "image_registry",
        "image_id": "",
        "image_name": image_name,
        "storage_bucket": str(args.datastore_id),
        "disk_ids": [],
        "image_format": args.image_format,
        "region": args.region,
    }

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)
        template = build_image_template(image_name, args.image_url, args.image_format, args.region)
        image_id = allocate_image(one, template, args.datastore_id)
        result["image_id"] = image_id
        result["disk_ids"] = [image_id]

        image_info = wait_for_image_state(
            one,
            image_id,
            allowed_states={"ready", "used", "used_persistent"},
            timeout=args.wait_timeout,
        )
        result["image_state"] = image_state_name(image_info)
        result["success"] = True
        result["message"] = f"Imported OpenNebula image {image_id}"
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
