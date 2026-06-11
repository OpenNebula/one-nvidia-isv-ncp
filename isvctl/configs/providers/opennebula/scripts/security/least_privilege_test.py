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

from common.control_plane import allocate_user, delete_user, get_one_server

TEST_NAME = "least_privilege_test"
NETWORK_SCOPE_MESSAGE = (
    "Not implemented - OpenNebula XML-RPC user/resource permissions do not validate source-CIDR policy scope"
)
DENIAL_MARKERS = (
    "not authorized",
    "not authorised",
    "not allowed",
    "permission",
    "user couldn't be authenticated",
    "auth",
)
NOT_ENOUGH_PARAMETERS = "not enough parameters"
IMAGE_LOCKED_FORCE_DELETE = "force delete"


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
            "out_of_scope_compute_denied": {
                "passed": False,
                "error": "minimal-role compute denial probe did not run",
            },
            "out_of_scope_storage_denied": {
                "passed": False,
                "error": "minimal-role storage denial probe did not run",
            },
            "out_of_scope_network_denied": {
                "passed": False,
                "error": "minimal-role network denial probe did not run",
            },
        },
    }


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
    template_id = _call_opennebula_variants(
        one.template.allocate,
        (template, False),
        (template,),
    )
    return str(int(template_id))


def _allocate_datablock_image(one: Any, name: str, datastore_id: int) -> str:
    """Allocate a small temporary datablock image and return its ID."""
    template = f"""
NAME = "{name}"
TYPE = "DATABLOCK"
SIZE = "1"
PERSISTENT = "NO"
DEV_PREFIX = "vd"
DESCRIPTION = "ISV minimal-role storage denial probe"
"""
    image_id = _call_opennebula_variants(
        one.image.allocate,
        (template, datastore_id, False),
        (template, datastore_id),
        (template,),
    )
    return str(int(image_id))


def _allocate_security_group(one: Any, name: str) -> str:
    """Allocate a temporary security group and return its ID."""
    template = f"""
NAME = "{name}"
DESCRIPTION = "ISV minimal-role network denial probe"
RULE = [
  PROTOCOL = "ICMP",
  RULE_TYPE = "OUTBOUND"
]
"""
    secgroup_id = _call_opennebula_variants(
        one.secgroup.allocate,
        (template,),
    )
    return str(int(secgroup_id))


def _chmod_template_owner_only(one: Any, template_id: str) -> None:
    """Set template permissions to owner-only use/manage when supported."""
    _call_opennebula_variants(
        one.template.chmod,
        (int(template_id), 1, 1, 0, 0, 0, 0, 0, 0, 0),
        (int(template_id), 600),
    )


def _chmod_image_owner_only(one: Any, image_id: str) -> None:
    """Set image permissions to owner-only use/manage when supported."""
    _call_opennebula_variants(
        one.image.chmod,
        (int(image_id), 1, 1, 0, 0, 0, 0, 0, 0, 0),
        (int(image_id), 600),
    )


def _chmod_security_group_owner_only(one: Any, secgroup_id: str) -> None:
    """Set security-group permissions to owner-only use/manage when supported."""
    _call_opennebula_variants(
        one.secgroup.chmod,
        (int(secgroup_id), 1, 1, 0, 0, 0, 0, 0, 0, 0),
        (int(secgroup_id), 600),
    )


def _can_read_template(one: Any, template_id: str) -> tuple[bool, str]:
    """Return whether the authenticated principal can read the VM template."""
    try:
        one.template.info(int(template_id))
        return True, ""
    except Exception as e:
        return False, str(e)


def _delete_image(one: Any, image_id: str) -> None:
    """Delete an image, retrying locked temporary images with force."""
    try:
        one.image.delete(int(image_id))
    except Exception as e:
        if IMAGE_LOCKED_FORCE_DELETE not in str(e).lower():
            raise
        one.image.delete(int(image_id), True)


def _denied_by_opennebula(error: str) -> bool:
    """Return whether an OpenNebula error represents permission denial."""
    normalized = error.lower()
    return any(marker in normalized for marker in DENIAL_MARKERS)


def _not_enough_parameters(error: Exception) -> bool:
    """Return whether OpenNebula rejected a pyone signature as too short."""
    return NOT_ENOUGH_PARAMETERS in str(error).lower()


def _call_opennebula_variants(method: Any, *variants: tuple[Any, ...]) -> Any:
    """Call a pyone method, trying variants rejected by local or XML-RPC arity checks."""
    last_error: Exception | None = None
    for args in variants:
        try:
            return method(*args)
        except TypeError as e:
            last_error = e
        except Exception as e:
            last_error = e
            if not _not_enough_parameters(e):
                raise
    if last_error is not None:
        raise last_error
    raise TypeError("no call signatures supplied")


def _run_step(label: str, call: Any) -> Any:
    """Run a setup step and annotate OpenNebula errors with the API operation."""
    try:
        return call()
    except Exception as e:
        raise RuntimeError(f"{label}: {e}") from e


def _probe_denied(operation: str, call: Any) -> tuple[bool, str]:
    """Run an out-of-scope OpenNebula API call and return whether it was denied."""
    try:
        call()
    except Exception as e:
        error = str(e)
        if _denied_by_opennebula(error):
            return True, error
        return False, f"{operation} failed, but not with a recognizable authorization denial: {error}"
    return False, f"{operation} unexpectedly succeeded"


def _mark_test(tests: dict[str, Any], name: str, passed: bool, message: str, probes: dict[str, Any]) -> None:
    """Update one test result."""
    tests[name] = {"passed": passed, "probes": probes}
    if passed:
        tests[name]["message"] = message
    else:
        tests[name]["error"] = message


def _mark_unrun_minimal_role_tests(tests: dict[str, Any], error: str) -> None:
    """Replace placeholder minimal-role errors with the real setup failure."""
    for name in (
        "out_of_scope_compute_denied",
        "out_of_scope_storage_denied",
        "out_of_scope_network_denied",
    ):
        result = tests.get(name, {})
        if result.get("passed") is False and str(result.get("error", "")).endswith("probe did not run"):
            result["error"] = f"minimal-role denial probe could not run: {error}"


def evaluate_least_privilege(
    *,
    region: str,
    xmlrpc_url: str,
    admin_auth: str,
    token_ttl_seconds: int,
    allowed_source_cidr: str,
    datastore_id: int,
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
    out_of_scope_template_id: str | None = None
    out_of_scope_image_id: str | None = None
    out_of_scope_secgroup_id: str | None = None
    cleanup_errors: list[str] = []

    try:
        allowed_password = secrets.token_urlsafe(24)
        denied_password = secrets.token_urlsafe(24)
        allowed_user_id = _run_step(
            "allocate allowed user",
            lambda: allocate_user(admin_one, allowed_username, allowed_password),
        )
        denied_user_id = _run_step(
            "allocate denied user",
            lambda: allocate_user(admin_one, denied_username, denied_password),
        )

        allowed_one = _run_step(
            "open allowed user session",
            lambda: get_one_server(xmlrpc_url, f"{allowed_username}:{allowed_password}"),
        )
        denied_one = _run_step(
            "open denied user session",
            lambda: get_one_server(xmlrpc_url, f"{denied_username}:{denied_password}"),
        )

        template_id = _run_step(
            "allocate allowed template",
            lambda: _allocate_template(allowed_one, f"isv-lp-template-{suffix}"),
        )
        _run_step("chmod allowed template", lambda: _chmod_template_owner_only(admin_one, template_id))
        out_of_scope_template_id = _run_step(
            "allocate out-of-scope template",
            lambda: _allocate_template(admin_one, f"isv-lp-deny-template-{suffix}"),
        )
        _run_step(
            "chmod out-of-scope template",
            lambda: _chmod_template_owner_only(admin_one, out_of_scope_template_id),
        )
        out_of_scope_image_id = _run_step(
            "allocate out-of-scope image",
            lambda: _allocate_datablock_image(admin_one, f"isv-lp-deny-image-{suffix}", datastore_id),
        )
        _run_step("chmod out-of-scope image", lambda: _chmod_image_owner_only(admin_one, out_of_scope_image_id))
        out_of_scope_secgroup_id = _run_step(
            "allocate out-of-scope security group",
            lambda: _allocate_security_group(admin_one, f"isv-lp-deny-sg-{suffix}"),
        )
        _run_step(
            "chmod out-of-scope security group",
            lambda: _chmod_security_group_owner_only(admin_one, out_of_scope_secgroup_id),
        )
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
        compute_denied, compute_error = _probe_denied(
            "one.template.info",
            lambda: allowed_one.template.info(int(out_of_scope_template_id)),
        )
        storage_denied, storage_error = _probe_denied(
            "one.image.info",
            lambda: allowed_one.image.info(int(out_of_scope_image_id)),
        )
        network_denied, network_error = _probe_denied(
            "one.secgroup.info",
            lambda: allowed_one.secgroup.info(int(out_of_scope_secgroup_id)),
        )
        _mark_test(
            result["tests"],
            "out_of_scope_compute_denied",
            compute_denied,
            "Minimal OpenNebula identity was denied out-of-scope VM template access"
            if compute_denied
            else compute_error,
            {
                "identity": result["test_identity"],
                "resource": f"opennebula:template/{out_of_scope_template_id}",
                "operation": "one.template.info",
                "denial_error": compute_error if compute_denied else "",
            },
        )
        _mark_test(
            result["tests"],
            "out_of_scope_storage_denied",
            storage_denied,
            "Minimal OpenNebula identity was denied out-of-scope image access"
            if storage_denied
            else storage_error,
            {
                "identity": result["test_identity"],
                "resource": f"opennebula:image/{out_of_scope_image_id}",
                "operation": "one.image.info",
                "denial_error": storage_error if storage_denied else "",
            },
        )
        _mark_test(
            result["tests"],
            "out_of_scope_network_denied",
            network_denied,
            "Minimal OpenNebula identity was denied out-of-scope security-group access"
            if network_denied
            else network_error,
            {
                "identity": result["test_identity"],
                "resource": f"opennebula:secgroup/{out_of_scope_secgroup_id}",
                "operation": "one.secgroup.info",
                "denial_error": network_error if network_denied else "",
            },
        )
        result["success"] = all(test["passed"] for test in result["tests"].values())
        if not result["success"]:
            result["error"] = "OpenNebula least-privilege validation did not satisfy all required policy dimensions"
        return result
    except Exception as e:
        error = str(e)
        result["error"] = error
        _mark_unrun_minimal_role_tests(result["tests"], error)
        return result
    finally:
        if out_of_scope_secgroup_id is not None:
            try:
                admin_one.secgroup.delete(int(out_of_scope_secgroup_id))
            except Exception as e:
                cleanup_errors.append(f"delete security group {out_of_scope_secgroup_id}: {e}")
        if out_of_scope_image_id is not None:
            try:
                _delete_image(admin_one, out_of_scope_image_id)
            except Exception as e:
                cleanup_errors.append(f"delete image {out_of_scope_image_id}: {e}")
        if out_of_scope_template_id is not None:
            try:
                admin_one.template.delete(int(out_of_scope_template_id))
            except Exception as e:
                cleanup_errors.append(f"delete template {out_of_scope_template_id}: {e}")
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
    parser.add_argument(
        "--datastore-id",
        type=int,
        default=int(os.environ.get("ONE_IMAGE_DATASTORE_ID", "1")),
        help="OpenNebula image datastore ID for temporary storage denial probes",
    )
    args = parser.parse_args()

    result = evaluate_least_privilege(
        region=args.region,
        xmlrpc_url=args.xmlrpc_url,
        admin_auth=args.auth,
        token_ttl_seconds=args.token_ttl_seconds,
        allowed_source_cidr=args.allowed_source_cidr,
        datastore_id=args.datastore_id,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
