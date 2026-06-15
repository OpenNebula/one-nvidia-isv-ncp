#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""CRUD OpenNebula images using the image datastore API."""

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
    get_value,
    image_state_name,
    wait_for_image_deleted,
    wait_for_image_state,
)


def test_get(one: Any, image_id: str) -> dict[str, Any]:
    """Read a single OpenNebula image by ID."""
    result: dict[str, Any] = {"passed": False}
    try:
        image_info = one.image.info(int(image_id))
        result["image_name"] = str(get_value(image_info, "NAME", ""))
        result["state"] = image_state_name(image_info)
        result["passed"] = True
        result["message"] = f"Described image {image_id}: state={result['state']}"
    except Exception as e:
        result["error"] = str(e)
    return result


def image_pool_entries(image_pool: Any) -> list[Any]:
    """Return image entries from an OpenNebula image pool object."""
    images = get_value(image_pool, "IMAGE", [])
    if images is None:
        return []
    if isinstance(images, list):
        return images
    return [images]


def test_list(one: Any, image_id: str) -> dict[str, Any]:
    """List images visible to the user and verify the target image appears."""
    result: dict[str, Any] = {"passed": False}
    try:
        try:
            image_pool = one.imagepool.info(-2, -1, -1)
        except TypeError:
            image_pool = one.imagepool.info()

        images = image_pool_entries(image_pool)
        image_ids = {str(get_value(image, "ID", "")) for image in images}
        result["image_count"] = len(images)
        result["passed"] = image_id in image_ids
        if result["passed"]:
            result["message"] = f"Found image {image_id} in {len(images)} visible image(s)"
        else:
            result["error"] = f"Image {image_id} not found in visible image list"
    except Exception as e:
        result["error"] = str(e)
    return result


def test_create(one: Any, image_id: str, datastore_id: int, wait_timeout: int) -> dict[str, Any]:
    """Create a copied image by cloning an existing OpenNebula image."""
    result: dict[str, Any] = {"passed": False}
    clone_name = f"isvtest-image-copy-{uuid.uuid4().hex[:8]}"
    try:
        try:
            copy_id = one.image.clone(int(image_id), clone_name, datastore_id)
        except TypeError:
            copy_id = one.image.clone(int(image_id), clone_name)

        copy_id = str(int(copy_id))
        result["image_id"] = copy_id
        result["image_name"] = clone_name
        image_info = wait_for_image_state(
            one,
            copy_id,
            allowed_states={"ready", "used", "used_persistent"},
            timeout=wait_timeout,
        )
        result["state"] = image_state_name(image_info)
        result["passed"] = True
        result["message"] = f"Cloned image {image_id} to {copy_id}"
    except Exception as e:
        result["error"] = str(e)
    return result


def test_delete(one: Any, image_id: str) -> dict[str, Any]:
    """Delete an OpenNebula image and verify it is gone."""
    result: dict[str, Any] = {"passed": False}
    try:
        one.image.delete(int(image_id))
        deleted = wait_for_image_deleted(one, image_id)
        result["passed"] = deleted
        result["message"] = f"Deleted image {image_id}" if deleted else f"Image {image_id} still exists"
        if not deleted:
            result["error"] = f"Image {image_id} still exists"
    except Exception as e:
        result["error"] = str(e)
    return result


def main() -> int:
    """Run OpenNebula image CRUD operations and emit structured JSON output."""
    parser = argparse.ArgumentParser(description="CRUD OpenNebula images")
    parser.add_argument("--image-id", required=True, help="Source image ID from upload_image")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--datastore-id", required=True, type=int, help="OpenNebula image datastore ID")
    parser.add_argument("--wait-timeout", default=600, type=int, help="Seconds to wait for cloned image readiness")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "image_registry",
        "image_id": args.image_id,
        "region": args.region,
        "operations": {
            "get": {"passed": False},
            "list": {"passed": False},
            "create": {"passed": False},
            "delete": {"passed": False},
        },
    }
    copy_id = ""

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)

        get_result = test_get(one, args.image_id)
        result["operations"]["get"] = get_result
        if not get_result["passed"]:
            raise RuntimeError(f"Get failed: {get_result.get('error')}")

        list_result = test_list(one, args.image_id)
        result["operations"]["list"] = list_result
        if not list_result["passed"]:
            raise RuntimeError(f"List failed: {list_result.get('error')}")

        create_result = test_create(one, args.image_id, args.datastore_id, args.wait_timeout)
        result["operations"]["create"] = create_result
        if not create_result["passed"]:
            raise RuntimeError(f"Create failed: {create_result.get('error')}")
        copy_id = create_result["image_id"]

        delete_result = test_delete(one, copy_id)
        result["operations"]["delete"] = delete_result
        if not delete_result["passed"]:
            raise RuntimeError(f"Delete failed: {delete_result.get('error')}")
        copy_id = ""

        result["success"] = True
    except Exception as e:
        result["error"] = str(e)
        if copy_id:
            try:
                one.image.delete(int(copy_id))
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
