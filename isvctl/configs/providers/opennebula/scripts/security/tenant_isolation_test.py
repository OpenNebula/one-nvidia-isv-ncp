#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula tenant isolation with real users, groups, VDCs, and resources."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.control_plane import allocate_group, allocate_user, delete_group, delete_user, get_one_server
from common.network import allocate_vnet, delete_vnet, quote

TEST_NAME = "tenant_isolation_test"
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


class Tenant:
    """Temporary OpenNebula tenant fixture."""

    def __init__(self, *, label: str, username: str, password: str, group_name: str, vdc_name: str) -> None:
        """Initialize a temporary OpenNebula tenant fixture."""
        self.label = label
        self.username = username
        self.password = password
        self.group_name = group_name
        self.vdc_name = vdc_name
        self.user_id: str | None = None
        self.group_id: str | None = None
        self.vdc_id: str | None = None
        self.template_id: str | None = None
        self.data_image_id: str | None = None
        self.storage_image_id: str | None = None
        self.secgroup_id: str | None = None
        self.vnet_id: str | None = None

    @property
    def identity(self) -> str:
        """Return the validation identity shown in result output."""
        if self.user_id:
            return f"opennebula:user/{self.username}:{self.user_id}"
        return f"opennebula:user/{self.username}"


def _base_result(region: str) -> dict[str, Any]:
    """Return the base tenant-isolation result payload."""
    return {
        "success": False,
        "platform": "security",
        "test_name": TEST_NAME,
        "region": region,
        "tenant_a_id": "",
        "tenant_b_id": "",
        "tests": {
            "network_isolated": {"passed": False, "error": "network isolation probe did not run"},
            "data_isolated": {"passed": False, "error": "data isolation probe did not run"},
            "compute_isolated": {"passed": False, "error": "compute isolation probe did not run"},
            "storage_isolated": {"passed": False, "error": "storage isolation probe did not run"},
        },
    }


def _mark_unrun_tests_failed(result: dict[str, Any], error: str) -> None:
    """Attach a setup failure to tenant-isolation probes that never ran."""
    for test in result.get("tests", {}).values():
        if test.get("passed") is False and str(test.get("error", "")).endswith("probe did not run"):
            test["error"] = f"setup failed before tenant-isolation probes: {error}"


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


def _denied_by_opennebula(error: str) -> bool:
    """Return whether an OpenNebula error represents permission denial."""
    normalized = error.lower()
    return any(marker in normalized for marker in DENIAL_MARKERS)


def _probe_denied(operation: str, call: Any) -> dict[str, Any]:
    """Run a cross-tenant API call and return the probe result."""
    try:
        call()
    except Exception as e:
        error = str(e)
        if _denied_by_opennebula(error):
            return {"passed": True, "operation": operation, "denial_error": error}
        return {
            "passed": False,
            "operation": operation,
            "error": f"{operation} failed, but not with a recognizable authorization denial: {error}",
        }
    return {"passed": False, "operation": operation, "error": f"{operation} unexpectedly succeeded"}


def _aggregate_probes(probes: list[dict[str, Any]], success_message: str) -> dict[str, Any]:
    """Return the check result for a group of negative probes."""
    passed = all(probe["passed"] for probe in probes)
    result: dict[str, Any] = {"passed": passed, "probes": probes}
    if passed:
        result["message"] = success_message
    else:
        result["error"] = "; ".join(
            probe.get("error", probe.get("operation", "")) for probe in probes if not probe["passed"]
        )
    return result


def _allocate_vdc(one: Any, name: str) -> str:
    """Allocate an OpenNebula VDC and return its ID."""
    return str(int(one.vdc.allocate(f"NAME = {quote(name)}")))


def _add_group_to_vdc(one: Any, vdc_id: str, group_id: str) -> None:
    """Add a group to a VDC across pyone method spellings."""
    method = getattr(one.vdc, "addgroup", None) or getattr(one.vdc, "add_group", None)
    if method is None:
        raise RuntimeError("OpenNebula VDC API does not expose addgroup")
    _call_opennebula_variants(method, (int(vdc_id), int(group_id)), (int(vdc_id), int(group_id), ""))


def _change_user_group(one: Any, user_id: str, group_id: str) -> None:
    """Set the user's primary group across pyone method spellings."""
    method = getattr(one.user, "chgrp", None) or getattr(one.user, "changegroup", None)
    if method is None:
        raise RuntimeError("OpenNebula user API does not expose chgrp")
    _call_opennebula_variants(method, (int(user_id), int(group_id)))


def _allocate_template(one: Any, name: str) -> str:
    """Allocate a minimal VM template and return its ID."""
    template = f"""
NAME = "{name}"
CPU = "1"
MEMORY = "64"
CONTEXT = [
  ISVTEST = "tenant-isolation"
]
"""
    template_id = _call_opennebula_variants(one.template.allocate, (template, False), (template,))
    return str(int(template_id))


def _allocate_datablock_image(one: Any, name: str, datastore_id: int, description: str) -> str:
    """Allocate a small temporary datablock image and return its ID."""
    template = f"""
NAME = "{name}"
TYPE = "DATABLOCK"
SIZE = "1"
PERSISTENT = "NO"
DEV_PREFIX = "vd"
DESCRIPTION = "{description}"
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
DESCRIPTION = "ISV tenant isolation network denial probe"
RULE = [
  PROTOCOL = "ICMP",
  RULE_TYPE = "OUTBOUND"
]
"""
    secgroup_id = _call_opennebula_variants(one.secgroup.allocate, (template,))
    return str(int(secgroup_id))


def _allocate_dummy_vnet(one: Any, name: str, cidr: str, cluster_id: int) -> str:
    """Allocate a temporary dummy virtual network and return its ID."""
    network = ipaddress.ip_network(cidr, strict=False)
    ar_ip = network.network_address + 1 if network.num_addresses > 2 else network.network_address
    template = "\n".join(
        [
            f"NAME = {quote(name)}",
            'DESCRIPTION = "ISV tenant isolation network denial probe"',
            'VN_MAD = "dummy"',
            'BRIDGE = "br5"',
            "AR = [",
            '  TYPE = "IP4",',
            f"  IP = {quote(ar_ip)},",
            '  SIZE = "1"',
            "]",
        ]
    )
    return str(allocate_vnet(one, template, cluster_id))


def _chmod_owner_only(resource: Any, resource_id: str) -> None:
    """Set an OpenNebula resource to owner-only use/manage permissions."""
    _call_opennebula_variants(
        resource.chmod,
        (int(resource_id), 1, 1, 0, 0, 0, 0, 0, 0, 0),
        (int(resource_id), 600),
    )


def _chown_to_tenant(resource: Any, resource_id: str, tenant: Tenant) -> None:
    """Assign an OpenNebula resource to the tenant user and group."""
    _call_opennebula_variants(
        resource.chown,
        (int(resource_id), int(tenant.user_id or ""), int(tenant.group_id or "")),
    )


def _delete_image(one: Any, image_id: str) -> None:
    """Delete an image, retrying locked temporary images with force."""
    try:
        one.image.delete(int(image_id))
    except Exception as e:
        if IMAGE_LOCKED_FORCE_DELETE not in str(e).lower():
            raise
        _call_opennebula_variants(one.image.delete, (int(image_id), True), (int(image_id), 1))


def _delete_vdc(one: Any, vdc_id: str) -> None:
    """Delete an OpenNebula VDC."""
    one.vdc.delete(int(vdc_id))


def _create_tenant(
    *,
    admin_one: Any,
    tenant: Tenant,
    xmlrpc_url: str,
    datastore_id: int,
    cluster_id: int,
    cidr: str,
) -> Any:
    """Create all resources owned by one temporary tenant."""
    tenant.group_id = _run_step(
        f"allocate group {tenant.group_name}",
        lambda: allocate_group(admin_one, tenant.group_name),
    )
    _run_step(
        f"assign user {tenant.username} to group {tenant.group_name}",
        lambda: _change_user_group(admin_one, tenant.user_id or "", tenant.group_id or ""),
    )
    tenant.vdc_id = _run_step(f"allocate VDC {tenant.vdc_name}", lambda: _allocate_vdc(admin_one, tenant.vdc_name))
    _run_step(
        f"add group {tenant.group_name} to VDC {tenant.vdc_name}",
        lambda: _add_group_to_vdc(admin_one, tenant.vdc_id or "", tenant.group_id or ""),
    )
    tenant_one = _run_step(
        f"open tenant session for {tenant.username}", lambda: _open_tenant_session(xmlrpc_url, tenant)
    )

    tenant.template_id = _run_step(
        f"allocate template for {tenant.username}",
        lambda: _allocate_template(admin_one, f"isv-ti-{tenant.label}-template-{uuid.uuid4().hex[:6]}"),
    )
    _run_step(
        f"assign template ownership to {tenant.username}",
        lambda: _chown_to_tenant(admin_one.template, tenant.template_id or "", tenant),
    )
    _run_step(
        "chmod tenant template owner-only", lambda: _chmod_owner_only(admin_one.template, tenant.template_id or "")
    )
    tenant.data_image_id = _run_step(
        f"allocate data image for {tenant.username}",
        lambda: _allocate_datablock_image(
            admin_one,
            f"isv-ti-{tenant.label}-data-{uuid.uuid4().hex[:6]}",
            datastore_id,
            "ISV tenant isolation data denial probe",
        ),
    )
    _run_step(
        f"assign data image ownership to {tenant.username}",
        lambda: _chown_to_tenant(admin_one.image, tenant.data_image_id or "", tenant),
    )
    _run_step(
        "chmod tenant data image owner-only", lambda: _chmod_owner_only(admin_one.image, tenant.data_image_id or "")
    )
    tenant.storage_image_id = _run_step(
        f"allocate storage image for {tenant.username}",
        lambda: _allocate_datablock_image(
            admin_one,
            f"isv-ti-{tenant.label}-storage-{uuid.uuid4().hex[:6]}",
            datastore_id,
            "ISV tenant isolation storage denial probe",
        ),
    )
    _run_step(
        f"assign storage image ownership to {tenant.username}",
        lambda: _chown_to_tenant(admin_one.image, tenant.storage_image_id or "", tenant),
    )
    _run_step(
        "chmod tenant storage image owner-only",
        lambda: _chmod_owner_only(admin_one.image, tenant.storage_image_id or ""),
    )
    tenant.secgroup_id = _run_step(
        f"allocate security group for {tenant.username}",
        lambda: _allocate_security_group(admin_one, f"isv-ti-{tenant.label}-sg-{uuid.uuid4().hex[:6]}"),
    )
    _run_step(
        f"assign security group ownership to {tenant.username}",
        lambda: _chown_to_tenant(admin_one.secgroup, tenant.secgroup_id or "", tenant),
    )
    _run_step(
        "chmod tenant security group owner-only",
        lambda: _chmod_owner_only(admin_one.secgroup, tenant.secgroup_id or ""),
    )
    tenant.vnet_id = _run_step(
        f"allocate virtual network for {tenant.username}",
        lambda: _allocate_dummy_vnet(
            admin_one, f"isv-ti-{tenant.label}-vnet-{uuid.uuid4().hex[:6]}", cidr, cluster_id
        ),
    )
    _run_step(
        f"assign virtual network ownership to {tenant.username}",
        lambda: _chown_to_tenant(admin_one.vn, tenant.vnet_id or "", tenant),
    )
    _run_step("chmod tenant virtual network owner-only", lambda: _chmod_owner_only(admin_one.vn, tenant.vnet_id or ""))
    return tenant_one


def _open_tenant_session(xmlrpc_url: str, tenant: Tenant) -> Any:
    """Return an OpenNebula XML-RPC client authenticated as the tenant user."""
    return get_one_server(xmlrpc_url, f"{tenant.username}:{tenant.password}")


def evaluate_tenant_isolation(
    *,
    region: str,
    xmlrpc_url: str,
    admin_auth: str,
    datastore_id: int,
    cluster_id: int,
) -> dict[str, Any]:
    """Provision two tenants and validate cross-tenant authorization denials."""
    result = _base_result(region)
    admin_one = get_one_server(xmlrpc_url, admin_auth)
    suffix = uuid.uuid4().hex[:8]
    tenant_a = Tenant(
        label="a",
        username=f"isv-ti-a-{suffix}",
        password=secrets.token_urlsafe(24),
        group_name=f"isv-ti-a-{suffix}",
        vdc_name=f"isv-ti-a-{suffix}",
    )
    tenant_b = Tenant(
        label="b",
        username=f"isv-ti-b-{suffix}",
        password=secrets.token_urlsafe(24),
        group_name=f"isv-ti-b-{suffix}",
        vdc_name=f"isv-ti-b-{suffix}",
    )
    tenant_a_one: Any | None = None
    cleanup_errors: list[str] = []

    try:
        tenant_a.user_id = _run_step(
            f"allocate user {tenant_a.username}",
            lambda: allocate_user(admin_one, tenant_a.username, tenant_a.password),
        )
        tenant_b.user_id = _run_step(
            f"allocate user {tenant_b.username}",
            lambda: allocate_user(admin_one, tenant_b.username, tenant_b.password),
        )
        result["tenant_a_id"] = tenant_a.identity
        result["tenant_b_id"] = tenant_b.identity
        tenant_a_one = _create_tenant(
            admin_one=admin_one,
            tenant=tenant_a,
            xmlrpc_url=xmlrpc_url,
            datastore_id=datastore_id,
            cluster_id=cluster_id,
            cidr="10.124.10.0/24",
        )
        _create_tenant(
            admin_one=admin_one,
            tenant=tenant_b,
            xmlrpc_url=xmlrpc_url,
            datastore_id=datastore_id,
            cluster_id=cluster_id,
            cidr="10.124.20.0/24",
        )

        result["tests"]["compute_isolated"] = _aggregate_probes(
            [
                _probe_denied(
                    "one.template.info",
                    lambda: tenant_a_one.template.info(int(tenant_b.template_id or "")),
                ),
                _probe_denied(
                    "one.template.delete",
                    lambda: tenant_a_one.template.delete(int(tenant_b.template_id or "")),
                ),
            ],
            "Tenant A was denied compute-template access to tenant B",
        )
        result["tests"]["data_isolated"] = _aggregate_probes(
            [
                _probe_denied("one.image.info", lambda: tenant_a_one.image.info(int(tenant_b.data_image_id or ""))),
            ],
            "Tenant A was denied data-image access to tenant B",
        )
        result["tests"]["storage_isolated"] = _aggregate_probes(
            [
                _probe_denied(
                    "one.image.clone",
                    lambda: tenant_a_one.image.clone(int(tenant_b.storage_image_id or ""), f"isv-ti-leak-{suffix}"),
                ),
                _probe_denied(
                    "one.image.delete",
                    lambda: _call_opennebula_variants(
                        tenant_a_one.image.delete,
                        (int(tenant_b.storage_image_id or ""), True),
                        (int(tenant_b.storage_image_id or ""), 1),
                    ),
                ),
            ],
            "Tenant A was denied storage-image operations against tenant B",
        )
        result["tests"]["network_isolated"] = _aggregate_probes(
            [
                _probe_denied(
                    "one.secgroup.chmod",
                    lambda: _chmod_owner_only(tenant_a_one.secgroup, tenant_b.secgroup_id or ""),
                ),
                _probe_denied(
                    "one.vn.chmod",
                    lambda: _chmod_owner_only(tenant_a_one.vn, tenant_b.vnet_id or ""),
                ),
            ],
            "Tenant A was denied network-resource access to tenant B",
        )
        result["success"] = all(test["passed"] for test in result["tests"].values())
        if not result["success"]:
            result["error"] = "OpenNebula tenant isolation validation found cross-tenant access"
        return result
    except Exception as e:
        result["error"] = str(e)
        _mark_unrun_tests_failed(result, result["error"])
        return result
    finally:
        for tenant in (tenant_b, tenant_a):
            for label, delete_call in (
                ("vnet", lambda t=tenant: delete_vnet(admin_one, t.vnet_id or "")),
                ("secgroup", lambda t=tenant: admin_one.secgroup.delete(int(t.secgroup_id or ""))),
                ("storage image", lambda t=tenant: _delete_image(admin_one, t.storage_image_id or "")),
                ("data image", lambda t=tenant: _delete_image(admin_one, t.data_image_id or "")),
                ("template", lambda t=tenant: admin_one.template.delete(int(t.template_id or ""))),
                ("VDC", lambda t=tenant: _delete_vdc(admin_one, t.vdc_id or "")),
                ("user", lambda t=tenant: delete_user(admin_one, t.user_id or "")),
                ("group", lambda t=tenant: delete_group(admin_one, t.group_id or "")),
            ):
                try:
                    if _tenant_field_present(tenant, label):
                        delete_call()
                except Exception as e:
                    cleanup_errors.append(f"delete {label} for {tenant.identity}: {e}")
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            result["success"] = False


def _tenant_field_present(tenant: Tenant, label: str) -> bool:
    """Return whether a tenant cleanup target exists."""
    return {
        "vnet": tenant.vnet_id,
        "secgroup": tenant.secgroup_id,
        "storage image": tenant.storage_image_id,
        "data image": tenant.data_image_id,
        "template": tenant.template_id,
        "VDC": tenant.vdc_id,
        "user": tenant.user_id,
        "group": tenant.group_id,
    }[label] is not None


def main() -> int:
    """Run OpenNebula tenant-isolation validation."""
    parser = argparse.ArgumentParser(description="OpenNebula tenant isolation test")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--xmlrpc-url", default=os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"))
    parser.add_argument("--auth", default=os.environ.get("ONE_AUTH", "oneadmin:opennebula"))
    parser.add_argument(
        "--datastore-id",
        type=int,
        default=int(os.environ.get("ONE_IMAGE_DATASTORE_ID", "1")),
        help="OpenNebula image datastore ID for temporary data/storage denial probes",
    )
    parser.add_argument(
        "--cluster-id",
        type=int,
        default=int(os.environ.get("ONE_CLUSTER_ID", "-1")),
        help="OpenNebula cluster ID for temporary virtual-network allocation",
    )
    args = parser.parse_args()

    result = evaluate_tenant_isolation(
        region=args.region,
        xmlrpc_url=args.xmlrpc_url,
        admin_auth=args.auth,
        datastore_id=args.datastore_id,
        cluster_id=args.cluster_id,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
