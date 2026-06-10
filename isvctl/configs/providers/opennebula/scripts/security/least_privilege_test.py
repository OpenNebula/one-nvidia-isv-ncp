#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula least-privilege permissions with temporary users."""

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

TEST_NAME = "least_privilege_test"
NETWORK_SCOPE_MESSAGE = (
    "Not implemented - OpenNebula XML-RPC user/resource permissions do not validate source-CIDR policy scope"
)


def _base_result(region: str, allowed_source_cidr: str) -> dict[str, Any]:
    """Return the base least-privilege result payload."""
    return {
        "success": False,
        "platform": "security",
        "test_name": TEST_NAME,
        "region": region,
        "test_identity": "",
        "allowed_resource": "",
        "allowed_source_cidr": allowed_source_cidr,
        "tests": {
            "policy_dimensions_user_based": {
                "passed": False,
                "error": "least-privilege user policy probe did not run",
            },
            "policy_dimensions_resource_based": {
                "passed": False,
                "error": "least-privilege resource policy probe did not run",
            },
            "policy_dimensions_network_based": {
                "passed": False,
                "error": NETWORK_SCOPE_MESSAGE,
            },
            "policy_dimensions_allowed_action_succeeds": {
                "passed": False,
                "error": "least-privilege allowed-action probe did not run",
            },
        },
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


def _allocate_template(one: Any, name: str) -> str:
    """Allocate a minimal VM template and return its ID."""
    template = f"""
NAME = "{name}"
CPU = "1"
MEMORY = "64"
CONTEXT = [
  ISVTEST = "least-privilege"
]
"""
    return str(int(one.template.allocate(template)))


def _chmod_template_owner_only(one: Any, template_id: str) -> None:
    """Set template permissions to owner-only use/manage/admin when supported."""
    call_with_compatible_signature(
        one.template.chmod,
        (int(template_id), 600),
        (int(template_id), 1, 1, 0, 0, 0, 0, 0, 0),
    )


def _can_read_template(one: Any, template_id: str) -> tuple[bool, str]:
    """Return whether the authenticated principal can read the VM template."""
    try:
        one.template.info(int(template_id))
        return True, ""
    except Exception as e:
        return False, str(e)


def _mark_test(tests: dict[str, Any], name: str, passed: bool, message: str, probes: dict[str, Any]) -> None:
    """Update one test result."""
    tests[name] = {"passed": passed, "probes": probes}
    if passed:
        tests[name]["message"] = message
    else:
        tests[name]["error"] = message


def evaluate_least_privilege(
    *,
    region: str,
    xmlrpc_url: str,
    admin_auth: str,
    token_ttl_seconds: int,
    allowed_source_cidr: str,
) -> dict[str, Any]:
    """Provision temporary principals and validate OpenNebula resource permissions."""
    result = _base_result(region, allowed_source_cidr)
    admin_one = get_one_server(xmlrpc_url, admin_auth)
    suffix = uuid.uuid4().hex[:8]
    allowed_username = f"isv-lp-allow-{suffix}"
    denied_username = f"isv-lp-deny-{suffix}"
    allowed_user_id: str | None = None
    denied_user_id: str | None = None
    template_id: str | None = None
    cleanup_errors: list[str] = []

    try:
        allowed_user_id = allocate_user(admin_one, allowed_username, secrets.token_urlsafe(24))
        denied_user_id = allocate_user(admin_one, denied_username, secrets.token_urlsafe(24))

        allowed_token = _create_login_token(admin_one, allowed_username, token_ttl_seconds)
        denied_token = _create_login_token(admin_one, denied_username, token_ttl_seconds)
        allowed_one = get_one_server(xmlrpc_url, _session_from_login_token(allowed_username, allowed_token))
        denied_one = get_one_server(xmlrpc_url, _session_from_login_token(denied_username, denied_token))

        template_id = _allocate_template(allowed_one, f"isv-lp-template-{suffix}")
        _chmod_template_owner_only(admin_one, template_id)
        result["test_identity"] = f"opennebula:user/{allowed_username}:{allowed_user_id}"
        result["allowed_resource"] = f"opennebula:template/{template_id}"

        allowed_can_read, allowed_error = _can_read_template(allowed_one, template_id)
        denied_can_read, denied_error = _can_read_template(denied_one, template_id)
        denied_blocked = not denied_can_read

        _mark_test(
            result["tests"],
            "policy_dimensions_allowed_action_succeeds",
            allowed_can_read,
            "Allowed OpenNebula user can read its owner-only VM template"
            if allowed_can_read
            else f"Allowed OpenNebula user could not read owner-only VM template: {allowed_error}",
            {
                "identity": result["test_identity"],
                "resource": result["allowed_resource"],
                "operation": "one.template.info",
            },
        )
        _mark_test(
            result["tests"],
            "policy_dimensions_user_based",
            denied_blocked,
            "Different OpenNebula user was denied access to the owner-only VM template"
            if denied_blocked
            else "Different OpenNebula user could read the owner-only VM template",
            {
                "denied_identity": f"opennebula:user/{denied_username}:{denied_user_id}",
                "resource": result["allowed_resource"],
                "operation": "one.template.info",
                "denial_error": denied_error,
            },
        )
        _mark_test(
            result["tests"],
            "policy_dimensions_resource_based",
            allowed_can_read and denied_blocked,
            "OpenNebula enforced permissions on the specific VM template resource"
            if allowed_can_read and denied_blocked
            else "OpenNebula did not prove resource-scoped permissions on the specific VM template",
            {
                "resource": result["allowed_resource"],
                "allowed_identity_read": allowed_can_read,
                "denied_identity_read": denied_can_read,
            },
        )
        _mark_test(
            result["tests"],
            "policy_dimensions_network_based",
            False,
            NETWORK_SCOPE_MESSAGE,
            {
                "allowed_source_cidr": allowed_source_cidr,
                "native_opennebula_permission_scope": ["user", "group", "other", "resource"],
                "source_cidr_enforced_by_probe": False,
            },
        )
        result["success"] = all(test["passed"] for test in result["tests"].values())
        if not result["success"]:
            result["error"] = "OpenNebula least-privilege validation did not satisfy all required policy dimensions"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result
    finally:
        if template_id is not None:
            try:
                admin_one.template.delete(int(template_id))
            except Exception as e:
                cleanup_errors.append(f"delete template {template_id}: {e}")
        for label, user_id in (("allowed user", allowed_user_id), ("denied user", denied_user_id)):
            if user_id is None:
                continue
            try:
                delete_user(admin_one, user_id)
            except Exception as e:
                cleanup_errors.append(f"delete {label} {user_id}: {e}")
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            result["success"] = False


def main() -> int:
    """Run OpenNebula least-privilege validation."""
    parser = argparse.ArgumentParser(description="OpenNebula least-privilege policy test")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--xmlrpc-url", default=os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"))
    parser.add_argument("--auth", default=os.environ.get("ONE_AUTH", "oneadmin:opennebula"))
    parser.add_argument(
        "--token-ttl-seconds",
        type=int,
        default=int(os.environ.get("ONE_SERVICE_ACCOUNT_TOKEN_TTL_SECONDS", "-1")),
    )
    parser.add_argument(
        "--allowed-source-cidr",
        default=os.environ.get("ONE_LEAST_PRIVILEGE_ALLOWED_SOURCE_CIDR", "not-validated-by-opennebula-xmlrpc"),
    )
    args = parser.parse_args()

    result = evaluate_least_privilege(
        region=args.region,
        xmlrpc_url=args.xmlrpc_url,
        admin_auth=args.auth,
        token_ttl_seconds=args.token_ttl_seconds,
        allowed_source_cidr=args.allowed_source_cidr,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
