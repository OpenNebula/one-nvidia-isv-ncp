#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula service-account authentication with a generated token."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import allocate_user, call_with_compatible_signature, delete_user, get_one_server, get_value

TEST_NAME = "sa_credential_test"


def _empty_result(region: str) -> dict[str, Any]:
    """Return the base service-account result payload."""
    return {
        "success": False,
        "platform": "security",
        "test_name": TEST_NAME,
        "region": region,
        "authenticated": False,
        "credential_type": "opennebula_auth_token",
        "identity": "",
        "expires_at": None,
    }


def _session_from_login_token(username: str, token: str) -> str:
    """Return a valid OpenNebula session string from one.user.login output."""
    return token if ":" in token else f"{username}:{token}"


def _create_login_token(one: Any, username: str, ttl_seconds: int) -> str:
    """Create an OpenNebula login token for a user."""
    token = call_with_compatible_signature(
        one.user.login,
        (username, "", ttl_seconds, -1),
        (username, "", ttl_seconds),
    )
    return str(token)


def evaluate_service_account(
    *,
    region: str,
    xmlrpc_url: str,
    admin_auth: str,
    token_ttl_seconds: int,
) -> dict[str, Any]:
    """Provision a temporary user, authenticate with its token, and clean up."""
    result = _empty_result(region)
    admin_one = get_one_server(xmlrpc_url, admin_auth)
    username = f"isv-sa-{uuid.uuid4().hex[:8]}"
    password = secrets.token_urlsafe(24)
    user_id: str | None = None

    try:
        user_id = allocate_user(admin_one, username, password)
        token = _create_login_token(admin_one, username, token_ttl_seconds)
        service_auth = _session_from_login_token(username, token)
        service_one = get_one_server(xmlrpc_url, service_auth)
        user_info = call_with_compatible_signature(
            service_one.user.info,
            (-1,),
            (-1, False, False),
        )

        identity_name = str(get_value(user_info, "NAME", username))
        identity_id = str(get_value(user_info, "ID", user_id))
        if identity_name != username:
            result["error"] = f"Authenticated identity mismatch: expected {username}, got {identity_name}"
            return result

        result.update(
            {
                "success": True,
                "authenticated": True,
                "identity": f"opennebula:user/{identity_name}:{identity_id}",
                "expires_at": None if token_ttl_seconds < 0 else f"ttl_seconds={token_ttl_seconds}",
            }
        )
        return result
    except Exception as e:
        result["error"] = str(e)
        return result
    finally:
        if user_id is not None:
            try:
                delete_user(admin_one, user_id)
            except Exception as e:
                result["cleanup_errors"] = [f"delete user {user_id}: {e}"]
                result["error"] = f"{result.get('error')}; cleanup failed: {e}" if result.get("error") else f"cleanup failed: {e}"
                result["success"] = False
                result["authenticated"] = False


def main() -> int:
    """Run OpenNebula service-account credential validation."""
    parser = argparse.ArgumentParser(description="OpenNebula service-account credential test")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--xmlrpc-url", default=os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"))
    parser.add_argument("--auth", default=os.environ.get("ONE_AUTH", "oneadmin:opennebula"))
    parser.add_argument(
        "--token-ttl-seconds",
        type=int,
        default=int(os.environ.get("ONE_SERVICE_ACCOUNT_TOKEN_TTL_SECONDS", "-1")),
        help="-1 creates a non-expiring token, matching OpenNebula service-account usage",
    )
    args = parser.parse_args()

    result = evaluate_service_account(
        region=args.region,
        xmlrpc_url=args.xmlrpc_url,
        admin_auth=args.auth,
        token_ttl_seconds=args.token_ttl_seconds,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
