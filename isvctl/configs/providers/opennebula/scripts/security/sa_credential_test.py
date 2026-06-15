#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula user tokens used as service-account credentials."""

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

from common.control_plane import allocate_user, call_with_compatible_signature, delete_user, get_one_server

TEST_NAME = "sa_credential_test"
NON_EXPIRING_TOKEN_TTL_SECONDS = -1


def _base_result(region: str) -> dict[str, Any]:
    """Return the base service-account credential result payload."""
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


def _create_non_expiring_token(one: Any, username: str) -> str:
    """Create an OpenNebula authentication token with expiration disabled."""
    token = call_with_compatible_signature(
        one.user.login,
        (username, "", NON_EXPIRING_TOKEN_TTL_SECONDS),
        (username, "", NON_EXPIRING_TOKEN_TTL_SECONDS, -1),
    )
    return str(token)


def evaluate_service_account_credential(*, region: str, xmlrpc_url: str, admin_auth: str) -> dict[str, Any]:
    """Create a temporary technical user and verify non-expiring token auth."""
    result = _base_result(region)
    admin_one = get_one_server(xmlrpc_url, admin_auth)
    username = f"isv-sa-test-{uuid.uuid4().hex[:8]}"
    password = secrets.token_urlsafe(24)
    user_id: str | None = None
    cleanup_errors: list[str] = []

    try:
        user_id = allocate_user(admin_one, username, password)
        user_one = get_one_server(xmlrpc_url, f"{username}:{password}")
        token = _create_non_expiring_token(user_one, username)
        service_one = get_one_server(xmlrpc_url, _session_from_login_token(username, token))
        service_one.system.version()

        result["authenticated"] = True
        result["identity"] = f"opennebula:user/{username}:{user_id}"
        result["success"] = True
        result["message"] = "OpenNebula technical user authenticated with non-expiring token credential"
    except Exception as e:
        result["error"] = str(e)
    finally:
        if user_id is not None:
            try:
                delete_user(admin_one, user_id)
            except Exception as e:
                cleanup_errors.append(f"delete user {user_id}: {e}")
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            cleanup_error = f"Cleanup failed: {'; '.join(cleanup_errors)}"
            result["error"] = f"{result['error']}; {cleanup_error}" if result.get("error") else cleanup_error
            result["success"] = False

    return result


def main() -> int:
    """Run OpenNebula service-account credential authentication test."""
    parser = argparse.ArgumentParser(description="OpenNebula service-account credential test")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--xmlrpc-url", default=os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"))
    parser.add_argument("--auth", default=os.environ.get("ONE_AUTH", "oneadmin:opennebula"))
    parser.add_argument(
        "--token-ttl-seconds",
        type=int,
        default=int(os.environ.get("ONE_SERVICE_ACCOUNT_TOKEN_TTL_SECONDS", "-1")),
        help="Accepted for config compatibility; this probe uses -1 to require a non-expiring token",
    )
    args = parser.parse_args()

    result = evaluate_service_account_credential(
        region=args.region,
        xmlrpc_url=args.xmlrpc_url,
        admin_auth=args.auth,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
