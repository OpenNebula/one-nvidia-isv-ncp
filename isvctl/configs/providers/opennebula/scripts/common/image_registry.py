#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Shared OpenNebula image-registry helpers."""

from __future__ import annotations

import time
from typing import Any


IMAGE_STATE_NAMES = {
    0: "init",
    1: "ready",
    2: "used",
    3: "disabled",
    4: "locked",
    5: "error",
    6: "clone",
    7: "delete",
    8: "used_persistent",
}


def get_one_server(xmlrpc_url: str, auth: str) -> Any:
    """Return an authenticated OpenNebula XML-RPC client."""
    try:
        import pyone
    except ImportError as e:
        raise RuntimeError("pyone is not installed. Install pyone to run OpenNebula provider scripts.") from e

    return pyone.OneServer(xmlrpc_url, session=auth)


def get_value(item: Any, key: str, default: Any = None) -> Any:
    """Read a dict key or object attribute."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def quote(value: object) -> str:
    """Render an OpenNebula template value."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def image_state_name(image_info: Any) -> str:
    """Return a human-readable OpenNebula image state."""
    state = get_value(image_info, "STATE", None)
    try:
        return IMAGE_STATE_NAMES.get(int(state), str(state))
    except (TypeError, ValueError):
        return str(state)


def wait_for_image_state(
    one: Any,
    image_id: str | int,
    *,
    allowed_states: set[str],
    timeout: int = 600,
    interval: int = 5,
) -> Any:
    """Wait until an image reaches one of the requested state names."""
    deadline = time.time() + timeout
    last_info = None

    while time.time() < deadline:
        last_info = one.image.info(int(image_id))
        state = image_state_name(last_info)
        if state in allowed_states:
            return last_info
        if state in {"error", "delete"}:
            raise RuntimeError(f"Image {image_id} entered state {state}")
        time.sleep(interval)

    state = image_state_name(last_info) if last_info is not None else "unknown"
    raise RuntimeError(f"Timed out waiting for image {image_id}; last state={state}")


def image_exists(one: Any, image_id: str | int) -> bool:
    """Return whether an image exists."""
    try:
        one.image.info(int(image_id))
    except Exception:
        return False
    return True


def wait_for_image_deleted(one: Any, image_id: str | int, timeout: int = 120, interval: int = 3) -> bool:
    """Wait until an image no longer exists."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        if not image_exists(one, image_id):
            return True
        time.sleep(interval)

    return False


def template_exists(one: Any, template_id: str | int) -> bool:
    """Return whether a VM template exists."""
    try:
        one.template.info(int(template_id))
    except Exception:
        return False
    return True


def wait_for_template_deleted(one: Any, template_id: str | int, timeout: int = 60, interval: int = 2) -> bool:
    """Wait until a VM template no longer exists."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        if not template_exists(one, template_id):
            return True
        time.sleep(interval)

    return False
