#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Shared OpenNebula control-plane helpers."""

from __future__ import annotations

from typing import Any


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


def call_with_compatible_signature(method: Any, *variants: tuple[Any, ...]) -> Any:
    """Call a pyone method with the first supported argument signature."""
    last_error: TypeError | None = None
    for args in variants:
        try:
            return method(*args)
        except TypeError as e:
            last_error = e
    if last_error is not None:
        raise last_error
    raise TypeError("no call signatures supplied")


def allocate_user(one: Any, username: str, password: str, auth_driver: str = "core") -> str:
    """Allocate an OpenNebula user and return its ID as a string."""
    user_id = call_with_compatible_signature(
        one.user.allocate,
        (username, password, auth_driver),
        (username, password),
    )
    return str(int(user_id))


def change_user_password(one: Any, user_id: str | int, password: str) -> None:
    """Change an OpenNebula user's password."""
    call_with_compatible_signature(
        one.user.passwd,
        (int(user_id), password),
        (int(user_id), password, ""),
    )


def delete_user(one: Any, user_id: str | int) -> None:
    """Delete an OpenNebula user."""
    one.user.delete(int(user_id))


def get_user_info(one: Any, user_id: str | int) -> Any:
    """Return OpenNebula user info across pyone versions."""
    return call_with_compatible_signature(
        one.user.info,
        (int(user_id),),
        (int(user_id), False, False),
    )


def allocate_group(one: Any, group_name: str) -> str:
    """Allocate an OpenNebula group and return its ID as a string."""
    return str(int(one.group.allocate(group_name)))


def delete_group(one: Any, group_id: str | int) -> None:
    """Delete an OpenNebula group."""
    one.group.delete(int(group_id))


def get_group_info(one: Any, group_id: str | int) -> Any:
    """Return OpenNebula group info."""
    return one.group.info(int(group_id))


def pool_entries(pool: Any, key: str) -> list[Any]:
    """Return scalar-or-list pool entries as a list."""
    entries = get_value(pool, key, [])
    if entries is None:
        return []
    if isinstance(entries, list):
        return entries
    return [entries]


def list_groups(one: Any) -> list[Any]:
    """Return OpenNebula groups visible to the authenticated principal."""
    pool = call_with_compatible_signature(
        one.grouppool.info,
        (),
        (-2, -1, -1),
    )
    return pool_entries(pool, "GROUP")


def find_group_by_name(one: Any, group_name: str) -> Any | None:
    """Find an OpenNebula group by name."""
    for group in list_groups(one):
        if str(get_value(group, "NAME", "")) == group_name:
            return group
    return None


def find_user_by_name(one: Any, username: str) -> Any | None:
    """Find an OpenNebula user by name."""
    pool = call_with_compatible_signature(
        one.userpool.info,
        (),
        (-2, -1, -1),
    )
    for user in pool_entries(pool, "USER"):
        if str(get_value(user, "NAME", "")) == username:
            return user
    return None
