#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""CRUD OpenNebula VM templates as OS install configurations."""

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
    quote,
    wait_for_template_deleted,
)


def build_template(name: str, *, image_id: str | None, region: str, updated: bool = False) -> str:
    """Build a minimal OpenNebula VM template for install-config CRUD validation."""
    lines = [
        f"NAME = {quote(name)}",
        "CPU = 1",
        "VCPU = 1",
        "MEMORY = 1024",
        f"DESCRIPTION = {quote('ISV validation install config')}",
        f"ISVTEST_REGION = {quote(region)}",
        f"ISVTEST_UPDATED = {quote(str(updated).lower())}",
    ]
    if image_id:
        lines.append(f"DISK = [ IMAGE_ID = {int(image_id)} ]")
    return "\n".join(lines)


def test_create(one: Any, name: str, image_id: str | None, region: str) -> dict[str, Any]:
    """Create an OpenNebula VM template."""
    result: dict[str, Any] = {"passed": False}
    try:
        template_id = str(int(one.template.allocate(build_template(name, image_id=image_id, region=region))))
        result["config_id"] = template_id
        result["config_name"] = name
        result["passed"] = True
        result["message"] = f"Created VM template {template_id}"
    except Exception as e:
        result["error"] = str(e)
    return result


def test_read(one: Any, template_id: str, expected_name: str) -> dict[str, Any]:
    """Read an OpenNebula VM template and verify its name."""
    result: dict[str, Any] = {"passed": False}
    try:
        template_info = one.template.info(int(template_id))
        name = str(get_value(template_info, "NAME", ""))
        result["config_name"] = name
        result["passed"] = name == expected_name
        result["message"] = f"Read VM template {template_id}"
        if name != expected_name:
            result["error"] = f"Name mismatch: expected {expected_name}, got {name}"
    except Exception as e:
        result["error"] = str(e)
    return result


def test_update(one: Any, template_id: str, name: str, image_id: str | None, region: str) -> dict[str, Any]:
    """Update an OpenNebula VM template."""
    result: dict[str, Any] = {"passed": False}
    try:
        one.template.update(int(template_id), build_template(name, image_id=image_id, region=region, updated=True), 0)
        template_info = one.template.info(int(template_id))
        template = get_value(template_info, "TEMPLATE", {})
        updated = str(get_value(template, "ISVTEST_UPDATED", "")).lower() == "true"
        result["passed"] = updated
        result["message"] = f"Updated VM template {template_id}"
        if not updated:
            result["error"] = "Updated marker not found after template.update"
    except Exception as e:
        result["error"] = str(e)
    return result


def test_delete(one: Any, template_id: str) -> dict[str, Any]:
    """Delete an OpenNebula VM template and verify it is gone."""
    result: dict[str, Any] = {"passed": False}
    try:
        one.template.delete(int(template_id))
        deleted = wait_for_template_deleted(one, template_id)
        result["passed"] = deleted
        result["message"] = f"Deleted VM template {template_id}" if deleted else f"VM template {template_id} still exists"
        if not deleted:
            result["error"] = f"VM template {template_id} still exists"
    except Exception as e:
        result["error"] = str(e)
    return result


def main() -> int:
    """Run OpenNebula install-config CRUD operations and emit structured JSON output."""
    parser = argparse.ArgumentParser(description="CRUD OpenNebula VM template install config")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--image-id", default="", help="Optional image ID to attach to the template")
    args = parser.parse_args()

    name = f"isvtest-install-config-{uuid.uuid4().hex[:8]}"
    image_id = args.image_id or None
    result: dict[str, Any] = {
        "success": False,
        "platform": "image_registry",
        "config_id": "",
        "config_name": name,
        "operations": {
            "create": {"passed": False},
            "read": {"passed": False},
            "update": {"passed": False},
            "delete": {"passed": False},
        },
    }
    template_id = ""

    try:
        one = get_one_server(args.xmlrpc_url, args.auth)

        create_result = test_create(one, name, image_id, args.region)
        result["operations"]["create"] = create_result
        if not create_result["passed"]:
            raise RuntimeError(f"Create failed: {create_result.get('error')}")
        template_id = create_result["config_id"]
        result["config_id"] = template_id

        read_result = test_read(one, template_id, name)
        result["operations"]["read"] = read_result
        if not read_result["passed"]:
            raise RuntimeError(f"Read failed: {read_result.get('error')}")

        update_result = test_update(one, template_id, name, image_id, args.region)
        result["operations"]["update"] = update_result
        if not update_result["passed"]:
            raise RuntimeError(f"Update failed: {update_result.get('error')}")

        delete_result = test_delete(one, template_id)
        result["operations"]["delete"] = delete_result
        if not delete_result["passed"]:
            raise RuntimeError(f"Delete failed: {delete_result.get('error')}")
        template_id = ""

        result["success"] = True
    except Exception as e:
        result["error"] = str(e)
        if template_id:
            try:
                one.template.delete(int(template_id))
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
