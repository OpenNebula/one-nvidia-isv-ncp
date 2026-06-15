# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for OpenNebula security scripts."""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from xmlrpc.client import Fault

import pytest

ISVCTL_ROOT = Path(__file__).resolve().parents[1]
OPENNEBULA_SECURITY_SCRIPTS = ISVCTL_ROOT / "configs" / "providers" / "opennebula" / "scripts" / "security"


def _load_security_script(script_name: str) -> ModuleType:
    """Load an OpenNebula security script as a module."""
    script_path = OPENNEBULA_SECURITY_SCRIPTS / script_name
    spec = importlib.util.spec_from_file_location(f"test_opennebula_{script_path.stem}", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _payload(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    """Return JSON emitted by a script main call."""
    return json.loads(capsys.readouterr().out)


def _write_logrotate_policy(tmp_path: Path, policy_body: str) -> tuple[Path, Path]:
    """Write a temporary active OpenNebula logrotate policy."""
    config_dir = tmp_path / "logrotate.d"
    config_dir.mkdir()
    opennebula_config = config_dir / "opennebula"
    opennebula_config.write_text(policy_body, encoding="utf-8")
    main_config = tmp_path / "logrotate.conf"
    main_config.write_text(f"weekly\ninclude {config_dir}\n", encoding="utf-8")
    return opennebula_config, main_config


def test_opennebula_api_endpoint_isolation_accepts_private_xmlrpc_url(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Private XML-RPC endpoints emit the ApiEndpointIsolationCheck contract."""
    module = _load_security_script("api_endpoint_test.py")

    monkeypatch.setattr(module, "_resolve_host", lambda _host: (["10.0.0.15"], None))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "api_endpoint_test.py",
            "--region",
            "one",
            "--xmlrpc-url",
            "http://one.example.internal:2633/RPC2",
        ],
    )

    exit_code = module.main()
    payload = _payload(capsys)

    assert exit_code == 0
    assert payload["success"] is True
    assert payload["test_name"] == "api_endpoint_isolation"
    assert payload["endpoints_tested"] == 1
    assert set(payload["tests"]) == {
        "probe_api_from_public",
        "probe_mgmt_from_public",
        "verify_private_only",
        "dns_not_public",
    }
    assert all(test["passed"] is True for test in payload["tests"].values())


def test_opennebula_api_endpoint_isolation_rejects_public_xmlrpc_url() -> None:
    """Globally routable XML-RPC endpoints fail the endpoint isolation checks."""
    module = _load_security_script("api_endpoint_test.py")

    payload = module.evaluate_endpoint("https://8.8.8.8:2633/RPC2")

    assert payload["success"] is False
    assert payload["tests"]["verify_private_only"]["passed"] is False
    assert payload["tests"]["dns_not_public"]["passed"] is False


def test_opennebula_api_endpoint_isolation_treats_unresolvable_dns_as_not_private() -> None:
    """Unresolvable DNS is not public DNS evidence but does not prove private-only routing."""
    module = _load_security_script("api_endpoint_test.py")

    def fail_resolve(_host: str) -> tuple[list[str], str]:
        """Return a fake DNS failure."""
        return [], str(socket.gaierror("not found"))

    module._resolve_host = fail_resolve
    payload = module.evaluate_endpoint("http://missing.example.invalid:2633/RPC2")

    assert payload["success"] is False
    assert payload["tests"]["probe_api_from_public"]["passed"] is True
    assert payload["tests"]["verify_private_only"]["passed"] is False
    assert payload["tests"]["dns_not_public"]["passed"] is True


@pytest.mark.parametrize(
    ("aspect", "expected_tests"),
    [
        (
            "bmc_management_network",
            {
                "dedicated_management_network",
                "restricted_management_routes",
                "tenant_network_not_management",
                "management_acl_enforced",
            },
        ),
        (
            "bmc_tenant_isolation",
            {
                "probe_bmc_from_tenant",
                "probe_ipmi_port",
                "probe_redfish_port",
                "reverse_path_check",
            },
        ),
        (
            "bmc_protocol_security",
            {
                "ipmi_disabled",
                "redfish_tls_enabled",
                "redfish_plain_http_disabled",
                "redfish_authentication_required",
                "redfish_authorization_enforced",
                "redfish_accounting_enabled",
            },
        ),
        (
            "bmc_bastion_access",
            {
                "bastion_identifiable",
                "management_ingress_via_bastion_only",
                "no_direct_public_route",
                "bastion_hardened",
            },
        ),
    ],
)
def test_opennebula_bmc_security_fails_not_implemented(aspect: str, expected_tests: set[str]) -> None:
    """OpenNebula BMC security checks fail until real implementations exist."""
    module = _load_security_script("bmc_not_implemented_test.py")

    payload = module.build_result(aspect=aspect, region="opennebula")

    assert payload["success"] is False
    assert payload["test_name"] == aspect
    assert payload["error"] == "Not implemented - OpenNebula BMC security validation is not implemented"
    assert set(payload["tests"]) == expected_tests
    for subtest in payload["tests"].values():
        assert subtest["passed"] is False
        assert "Not implemented" in subtest["error"]
        assert subtest["probes"]["bmc_endpoints_checked"] == 0


def test_opennebula_centralized_kms_fails_not_implemented() -> None:
    """OpenNebula centralized KMS check fails until a real implementation exists."""
    module = _load_security_script("centralized_kms_not_implemented_test.py")

    payload = module.build_result(region="opennebula")

    assert payload["success"] is False
    assert payload["test_name"] == "centralized_kms_test"
    assert payload["error"] == "Not implemented - OpenNebula centralized KMS validation is not implemented"
    assert payload["kms_keys_total"] == 0
    assert payload["encrypted_resources_inspected"] == 0
    assert payload["non_kms_resources"] == 0
    assert set(payload["tests"]) == {
        "kms_service_reachable",
        "kms_keys_present",
        "all_encrypted_resources_use_kms",
    }
    for subtest in payload["tests"].values():
        assert subtest["passed"] is False
        assert "Not implemented" in subtest["error"]


@pytest.mark.parametrize(
    ("aspect", "expected_tests"),
    [
        ("cert_rotation_test", {"cert_inventory_non_empty", "no_certs_out_of_policy", "rotation_evidence_present"}),
        (
            "customer_managed_key_test",
            {
                "customer_managed_key_available",
                "key_manager_is_customer",
                "encrypt_decrypt_roundtrip",
                "resource_encrypted_with_customer_key",
                "provider_managed_key_not_used",
            },
        ),
        ("insecure_protocols_test", {"sslv3_disabled", "tlsv1_0_disabled", "tlsv1_1_disabled", "plain_http_disabled"}),
        (
            "kms_encryption_options_test",
            {"provider_managed_key_available", "customer_managed_key_available", "both_options_supported"},
        ),
        ("mfa_enforcement", {"root_mfa_enabled", "console_users_mfa", "api_mfa_policy", "cli_mfa_policy"}),
        (
            "minimal_role_enforcement_test",
            {
                "out_of_scope_compute_denied",
                "out_of_scope_storage_denied",
                "out_of_scope_network_denied",
            },
        ),
        (
            "oidc_user_auth_test",
            {
                "valid_token_accepted",
                "bad_signature_rejected",
                "wrong_issuer_rejected",
                "wrong_audience_rejected",
                "expired_token_rejected",
                "missing_required_claim_rejected",
                "discovery_and_jwks_reachable",
            },
        ),
        (
            "tenant_isolation_test",
            {
                "network_isolated",
                "data_isolated",
                "compute_isolated",
                "storage_isolated",
            },
        ),
    ],
)
def test_opennebula_security_checks_fail_not_implemented(aspect: str, expected_tests: set[str]) -> None:
    """Selected OpenNebula security checks fail until real implementations exist."""
    module = _load_security_script("security_not_implemented_test.py")

    payload = module.build_result(aspect=aspect, region="opennebula")

    assert payload["success"] is False
    assert payload["test_name"] == aspect
    assert payload["error"] == "Not implemented - OpenNebula security validation is not implemented"
    assert set(payload["tests"]) == expected_tests
    if aspect == "tenant_isolation_test":
        assert payload["tenant_a_id"] == "opennebula-tenant-a"
        assert payload["tenant_b_id"] == "opennebula-tenant-b"
    for subtest in payload["tests"].values():
        assert subtest["passed"] is False
        assert "Not implemented" in subtest["error"]


def test_opennebula_service_account_authenticates_technical_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OpenNebula service-account check uses a non-expiring technical-user token."""
    module = _load_security_script("sa_credential_test.py")
    state: dict[str, Any] = {"deleted_users": [], "login_calls": [], "sessions": []}

    class FakeAdminUser:
        """Fake admin-side user endpoint."""

        def allocate(self, username: str, password: str, _auth_driver: str = "core") -> int:
            """Allocate a fake technical user."""
            assert username.startswith("isv-sa-test-")
            assert password
            return 51

        def login(self, username: str, token: str, ttl_seconds: int) -> str:
            """Create a fake non-expiring token."""
            state["login_calls"].append((username, token, ttl_seconds))
            assert username.startswith("isv-sa-test-")
            assert token == ""
            assert ttl_seconds == -1
            return f"token-{username}"

        def delete(self, user_id: int) -> None:
            """Delete fake users."""
            state["deleted_users"].append(user_id)

    class FakeSystem:
        """Fake OpenNebula system endpoint."""

        def version(self) -> str:
            """Return a fake OpenNebula version."""
            return "6.10.0"

    admin_one = SimpleNamespace(user=FakeAdminUser())
    user_one = SimpleNamespace(user=FakeAdminUser())
    service_one = SimpleNamespace(system=FakeSystem())

    def fake_get_one_server(_xmlrpc_url: str, auth: str) -> Any:
        """Return fake clients by auth session."""
        state["sessions"].append(auth)
        if auth == "oneadmin:opennebula":
            return admin_one
        if auth.startswith("isv-sa-test-") and ":token-isv-sa-test-" in auth:
            return service_one
        if auth.startswith("isv-sa-test-"):
            return user_one
        raise AssertionError(f"unexpected auth session: {auth}")

    monkeypatch.setattr(module, "get_one_server", fake_get_one_server)

    payload = module.evaluate_service_account_credential(
        region="opennebula",
        xmlrpc_url="http://one.example.internal:2633/RPC2",
        admin_auth="oneadmin:opennebula",
    )

    assert payload["success"] is True
    assert payload["authenticated"] is True
    assert payload["credential_type"] == "opennebula_auth_token"
    assert payload["identity"].startswith("opennebula:user/isv-sa-test-")
    assert payload["identity"].endswith(":51")
    assert payload["expires_at"] is None
    assert state["login_calls"]
    assert state["deleted_users"] == [51]
    assert len(state["sessions"]) == 3


def test_opennebula_least_privilege_uses_real_permissions_and_fails_network_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OpenNebula least-privilege check exercises permissions and reports missing source-CIDR scope."""
    module = _load_security_script("least_privilege_test.py")
    state: dict[str, Any] = {
        "allocated_images": [],
        "allocated_secgroups": [],
        "deleted_templates": [],
        "deleted_images": [],
        "deleted_secgroups": [],
        "deleted_users": [],
        "chmod_templates": [],
        "chmod_images": [],
        "chmod_secgroups": [],
        "sessions": {},
    }

    class FakeAdminUser:
        """Fake admin-side user endpoint."""

        def allocate(self, username: str, _password: str, _auth_driver: str = "core") -> int:
            """Allocate fake users."""
            user_id = 41 if "-allow-" in username else 42
            state["sessions"][username] = f"{username}:token-{username}"
            return user_id

        def login(self, username: str, token: str, ttl_seconds: int, egid: int = -1) -> str:
            """Fail if the least-privilege probe uses OpenNebula login-token creation."""
            raise AssertionError(f"unexpected login-token creation for {username}:{token}:{ttl_seconds}:{egid}")

        def delete(self, user_id: int) -> None:
            """Delete fake users."""
            state["deleted_users"].append(user_id)

    class FakeAdminTemplate:
        """Fake admin-side template endpoint."""

        def allocate(self, template: str) -> int:
            """Allocate a fake admin-owned VM template."""
            assert "isv-lp-deny-template" in template
            return 78

        def chmod(self, template_id: int, mode: int) -> None:
            """Record template permissions."""
            state["chmod_templates"].append((template_id, mode))

        def delete(self, template_id: int) -> None:
            """Delete fake templates."""
            state["deleted_templates"].append(template_id)

    class FakeAdminImage:
        """Fake admin-side image endpoint."""

        def allocate(self, template: str, datastore_id: int) -> int:
            """Allocate a fake admin-owned image."""
            assert "DATABLOCK" in template
            assert datastore_id == 1
            state["allocated_images"].append((template, datastore_id))
            return 88

        def chmod(self, image_id: int, mode: int) -> None:
            """Record image permissions."""
            state["chmod_images"].append((image_id, mode))

        def delete(self, image_id: int) -> None:
            """Delete fake images."""
            state["deleted_images"].append(image_id)

    class FakeAdminSecgroup:
        """Fake admin-side security-group endpoint."""

        def allocate(self, template: str) -> int:
            """Allocate a fake admin-owned security group."""
            assert "isv-lp-deny-sg" in template
            state["allocated_secgroups"].append(template)
            return 99

        def chmod(self, secgroup_id: int, mode: int) -> None:
            """Record security-group permissions."""
            state["chmod_secgroups"].append((secgroup_id, mode))

        def delete(self, secgroup_id: int) -> None:
            """Delete fake security groups."""
            state["deleted_secgroups"].append(secgroup_id)

    class FakeAllowedTemplate:
        """Fake allowed-user template endpoint."""

        def allocate(self, template: str) -> int:
            """Allocate a fake VM template."""
            assert "ISVTEST" in template
            return 77

        def info(self, template_id: int) -> SimpleNamespace:
            """Allow owner reads."""
            if template_id == 78:
                raise RuntimeError("not authorized")
            assert template_id == 77
            return SimpleNamespace(ID=77, NAME="isv-lp-template")

    class FakeAllowedImage:
        """Fake allowed-user image endpoint."""

        def info(self, image_id: int) -> None:
            """Deny reads of an admin-owned image."""
            assert image_id == 88
            raise RuntimeError("not authorized")

    class FakeAllowedSecgroup:
        """Fake allowed-user security-group endpoint."""

        def info(self, secgroup_id: int) -> None:
            """Deny reads of an admin-owned security group."""
            assert secgroup_id == 99
            raise RuntimeError("not authorized")

    class FakeDeniedTemplate:
        """Fake denied-user template endpoint."""

        def info(self, template_id: int) -> None:
            """Deny non-owner reads."""
            assert template_id == 77
            raise RuntimeError("not authorized")

    admin_one = SimpleNamespace(
        user=FakeAdminUser(),
        template=FakeAdminTemplate(),
        image=FakeAdminImage(),
        secgroup=FakeAdminSecgroup(),
    )
    allowed_one = SimpleNamespace(
        template=FakeAllowedTemplate(),
        image=FakeAllowedImage(),
        secgroup=FakeAllowedSecgroup(),
    )
    denied_one = SimpleNamespace(template=FakeDeniedTemplate())

    def fake_get_one_server(_xmlrpc_url: str, auth: str) -> Any:
        """Return fake clients by auth session."""
        if auth == "oneadmin:opennebula":
            return admin_one
        if "-allow-" in auth:
            return allowed_one
        if "-deny-" in auth:
            return denied_one
        raise AssertionError(f"unexpected auth session: {auth}")

    monkeypatch.setattr(module, "get_one_server", fake_get_one_server)

    payload = module.evaluate_least_privilege(
        region="opennebula",
        xmlrpc_url="http://one.example.internal:2633/RPC2",
        admin_auth="oneadmin:opennebula",
        token_ttl_seconds=-1,
        allowed_source_cidr="not-validated-by-opennebula-xmlrpc",
        datastore_id=1,
    )

    assert payload["success"] is False
    assert payload["test_identity"].startswith("opennebula:user/isv-lp-allow-")
    assert payload["test_identity"].endswith(":41")
    assert payload["allowed_resource"] == "opennebula:template/77"
    assert payload["allowed_source_cidr"] == "not-validated-by-opennebula-xmlrpc"
    assert payload["tests"]["policy_dimensions_allowed_action_succeeds"]["passed"] is True
    assert payload["tests"]["policy_dimensions_user_based"]["passed"] is True
    assert payload["tests"]["policy_dimensions_resource_based"]["passed"] is True
    assert payload["tests"]["policy_dimensions_network_based"]["passed"] is False
    assert payload["tests"]["out_of_scope_compute_denied"]["passed"] is True
    assert payload["tests"]["out_of_scope_storage_denied"]["passed"] is True
    assert payload["tests"]["out_of_scope_network_denied"]["passed"] is True
    assert "source-CIDR" in payload["tests"]["policy_dimensions_network_based"]["error"]
    assert state["chmod_templates"] == [(77, 600), (78, 600)]
    assert state["chmod_images"] == [(88, 600)]
    assert state["chmod_secgroups"] == [(99, 600)]
    assert state["deleted_secgroups"] == [99]
    assert state["deleted_images"] == [88]
    assert state["deleted_templates"] == [78, 77]
    assert state["deleted_users"] == [41, 42]


def test_opennebula_least_privilege_chmod_uses_full_permission_signature() -> None:
    """OpenNebula chmod expanded signatures include all owner/group/other bits."""
    module = _load_security_script("least_privilege_test.py")
    chmod_calls: dict[str, list[tuple[Any, ...]]] = {"template": [], "image": [], "secgroup": []}

    def fake_chmod(kind: str) -> Any:
        """Return a chmod method that requires the XML-RPC expanded signature."""

        def chmod(*args: Any) -> None:
            chmod_calls[kind].append(args)
            if len(args) != 10:
                raise Fault(-501, "Not enough parameters")

        return chmod

    one = SimpleNamespace(
        template=SimpleNamespace(chmod=fake_chmod("template")),
        image=SimpleNamespace(chmod=fake_chmod("image")),
        secgroup=SimpleNamespace(chmod=fake_chmod("secgroup")),
    )

    module._chmod_template_owner_only(one, "77")
    module._chmod_image_owner_only(one, "88")
    module._chmod_security_group_owner_only(one, "99")

    assert chmod_calls["template"] == [(77, 1, 1, 0, 0, 0, 0, 0, 0, 0)]
    assert chmod_calls["image"] == [(88, 1, 1, 0, 0, 0, 0, 0, 0, 0)]
    assert chmod_calls["secgroup"] == [(99, 1, 1, 0, 0, 0, 0, 0, 0, 0)]


def test_opennebula_least_privilege_image_cleanup_retries_locked_image_with_force() -> None:
    """Locked temporary images are force-deleted during cleanup."""
    module = _load_security_script("least_privilege_test.py")
    delete_calls: list[tuple[Any, ...]] = []

    def delete(*args: Any) -> None:
        delete_calls.append(args)
        if args == (88,):
            raise RuntimeError("Image locked, use --force flag to remove the image. Force delete may leave files")

    one = SimpleNamespace(image=SimpleNamespace(delete=delete))

    module._delete_image(one, "88")

    assert delete_calls == [(88,), (88, True)]


def test_opennebula_tenant_isolation_uses_real_tenant_denials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OpenNebula tenant-isolation check passes only after cross-tenant API denials."""
    module = _load_security_script("tenant_isolation_test.py")
    state: dict[str, Any] = {
        "sessions": [],
        "user_chgrp": [],
        "vdc_groups": [],
        "chown": [],
        "chmod": [],
        "probes": [],
        "deleted": [],
    }

    class FakeAdminUser:
        """Fake admin-side user endpoint."""

        def allocate(self, username: str, _password: str, _auth_driver: str = "core") -> int:
            """Allocate fake tenant users."""
            return 101 if "-a-" in username else 102

        def chgrp(self, user_id: int, group_id: int) -> None:
            """Assign fake users to fake groups."""
            state["user_chgrp"].append((user_id, group_id))

        def delete(self, user_id: int) -> None:
            """Delete fake users."""
            state["deleted"].append(("user", user_id))

    class FakeAdminGroup:
        """Fake admin-side group endpoint."""

        def allocate(self, group_name: str) -> int:
            """Allocate fake tenant groups."""
            return 201 if "-a-" in group_name else 202

        def delete(self, group_id: int) -> None:
            """Delete fake groups."""
            state["deleted"].append(("group", group_id))

    class FakeAdminVdc:
        """Fake admin-side VDC endpoint."""

        def allocate(self, template: str) -> int:
            """Allocate fake tenant VDCs."""
            assert template.startswith('NAME = "isv-ti-')
            return 301 if "-a-" in template else 302

        def addgroup(self, vdc_id: int, group_id: int) -> None:
            """Assign groups to VDCs."""
            state["vdc_groups"].append((vdc_id, group_id))

        def delete(self, vdc_id: int) -> None:
            """Delete fake VDCs."""
            state["deleted"].append(("vdc", vdc_id))

    class FakeAdminResource:
        """Fake admin-side resource endpoint."""

        def __init__(self, kind: str) -> None:
            self.kind = kind

        def allocate(self, template: str, *_args: Any) -> int:
            """Allocate fake tenant-owned fixture resources as admin."""
            if self.kind == "template":
                assert "tenant-isolation" in template
                return 401 if "-a-" in template else 402
            if self.kind == "image":
                if "-a-data-" in template:
                    return 501
                if "-a-storage-" in template:
                    return 502
                if "-b-data-" in template:
                    return 503
                if "-b-storage-" in template:
                    return 504
            if self.kind == "secgroup":
                return 601 if "-a-" in template else 602
            if self.kind == "vn":
                assert 'VN_MAD = "dummy"' in template
                assert "PHYDEV" not in template
                return 701 if "-a-" in template else 702
            raise AssertionError(f"unexpected {self.kind} allocation template: {template}")

        def chown(self, resource_id: int, user_id: int, group_id: int) -> None:
            """Assign fake resources to tenant users and groups."""
            state["chown"].append((self.kind, resource_id, user_id, group_id))

        def chmod(self, resource_id: int, mode: int) -> None:
            """Record owner-only permission changes."""
            state["chmod"].append((self.kind, resource_id, mode))

        def delete(self, resource_id: int, *_args: Any) -> None:
            """Delete fake resources."""
            state["deleted"].append((self.kind, resource_id))

    class FakeTenantTemplate:
        """Fake tenant template endpoint."""

        def __init__(self, tenant: str) -> None:
            self.tenant = tenant

        def allocate(self, template: str) -> int:
            """Allocate tenant-owned templates."""
            assert "tenant-isolation" in template
            return 401 if self.tenant == "a" else 402

        def info(self, template_id: int) -> None:
            """Deny tenant A reads of tenant B templates."""
            state["probes"].append(("template.info", self.tenant, template_id))
            if self.tenant == "a" and template_id == 402:
                raise RuntimeError("not authorized")
            raise AssertionError(f"unexpected template.info {self.tenant=} {template_id=}")

        def delete(self, template_id: int) -> None:
            """Deny tenant A deletes of tenant B templates."""
            state["probes"].append(("template.delete", self.tenant, template_id))
            if self.tenant == "a" and template_id == 402:
                raise RuntimeError("not authorized")
            raise AssertionError(f"unexpected template.delete {self.tenant=} {template_id=}")

    class FakeTenantImage:
        """Fake tenant image endpoint."""

        def __init__(self, tenant: str) -> None:
            self.tenant = tenant

        def allocate(self, template: str, datastore_id: int) -> int:
            """Allocate tenant-owned data/storage images."""
            assert datastore_id == 1
            if self.tenant == "a" and "-data-" in template:
                return 501
            if self.tenant == "a" and "-storage-" in template:
                return 502
            if self.tenant == "b" and "-data-" in template:
                return 503
            if self.tenant == "b" and "-storage-" in template:
                return 504
            raise AssertionError(f"unexpected image template {template}")

        def info(self, image_id: int) -> None:
            """Deny tenant A reads of tenant B data images."""
            state["probes"].append(("image.info", self.tenant, image_id))
            if self.tenant == "a" and image_id == 503:
                raise RuntimeError("not authorized")
            raise AssertionError(f"unexpected image.info {self.tenant=} {image_id=}")

        def clone(self, image_id: int, _name: str) -> None:
            """Deny tenant A clones of tenant B storage images."""
            state["probes"].append(("image.clone", self.tenant, image_id))
            if self.tenant == "a" and image_id == 504:
                raise RuntimeError("not authorized")
            raise AssertionError(f"unexpected image.clone {self.tenant=} {image_id=}")

        def delete(self, image_id: int, force: bool = False) -> None:
            """Deny tenant A deletes of tenant B storage images."""
            state["probes"].append(("image.delete", self.tenant, image_id, force))
            if self.tenant == "a" and image_id == 504 and force is True:
                raise RuntimeError("not authorized")
            raise AssertionError(f"unexpected image.delete {self.tenant=} {image_id=} {force=}")

    class FakeTenantSecgroup:
        """Fake tenant security-group endpoint."""

        def __init__(self, tenant: str) -> None:
            self.tenant = tenant

        def allocate(self, _template: str) -> int:
            """Allocate tenant-owned security groups."""
            return 601 if self.tenant == "a" else 602

        def chmod(self, secgroup_id: int, *_args: Any) -> None:
            """Deny tenant A permission changes on tenant B security groups."""
            state["probes"].append(("secgroup.chmod", self.tenant, secgroup_id))
            if self.tenant == "a" and secgroup_id == 602:
                raise RuntimeError("not authorized")
            raise AssertionError(f"unexpected secgroup.chmod {self.tenant=} {secgroup_id=}")

    class FakeTenantVn:
        """Fake tenant virtual-network endpoint."""

        def __init__(self, tenant: str) -> None:
            self.tenant = tenant

        def allocate(self, _template: str, _cluster_id: int = -1) -> int:
            """Allocate tenant-owned virtual networks."""
            return 701 if self.tenant == "a" else 702

        def chmod(self, vnet_id: int, *_args: Any) -> None:
            """Deny tenant A permission changes on tenant B virtual networks."""
            state["probes"].append(("vn.chmod", self.tenant, vnet_id))
            if self.tenant == "a" and vnet_id == 702:
                raise RuntimeError("not authorized")
            raise AssertionError(f"unexpected vn.chmod {self.tenant=} {vnet_id=}")

    admin_one = SimpleNamespace(
        user=FakeAdminUser(),
        group=FakeAdminGroup(),
        vdc=FakeAdminVdc(),
        template=FakeAdminResource("template"),
        image=FakeAdminResource("image"),
        secgroup=FakeAdminResource("secgroup"),
        vn=FakeAdminResource("vn"),
    )
    tenant_a_one = SimpleNamespace(
        template=FakeTenantTemplate("a"),
        image=FakeTenantImage("a"),
        secgroup=FakeTenantSecgroup("a"),
        vn=FakeTenantVn("a"),
    )
    tenant_b_one = SimpleNamespace(
        template=FakeTenantTemplate("b"),
        image=FakeTenantImage("b"),
        secgroup=FakeTenantSecgroup("b"),
        vn=FakeTenantVn("b"),
    )

    def fake_get_one_server(_xmlrpc_url: str, auth: str) -> Any:
        """Return fake clients by auth session."""
        state["sessions"].append(auth)
        if auth == "oneadmin:opennebula":
            return admin_one
        if "isv-ti-a-" in auth:
            return tenant_a_one
        if "isv-ti-b-" in auth:
            return tenant_b_one
        raise AssertionError(f"unexpected auth session: {auth}")

    monkeypatch.setattr(module, "get_one_server", fake_get_one_server)

    payload = module.evaluate_tenant_isolation(
        region="opennebula",
        xmlrpc_url="http://one.example.internal:2633/RPC2",
        admin_auth="oneadmin:opennebula",
        datastore_id=1,
        cluster_id=-1,
    )

    assert payload["success"] is True
    assert payload["tenant_a_id"].startswith("opennebula:user/isv-ti-a-")
    assert payload["tenant_a_id"].endswith(":101")
    assert payload["tenant_b_id"].startswith("opennebula:user/isv-ti-b-")
    assert payload["tenant_b_id"].endswith(":102")
    assert all(test["passed"] is True for test in payload["tests"].values())
    assert state["user_chgrp"] == [(101, 201), (102, 202)]
    assert state["vdc_groups"] == [(301, 201), (302, 202)]
    assert ("template", 401, 101, 201) in state["chown"]
    assert ("template", 402, 102, 202) in state["chown"]
    assert ("image", 503, 102, 202) in state["chown"]
    assert ("secgroup", 602, 102, 202) in state["chown"]
    assert ("vn", 702, 102, 202) in state["chown"]
    assert ("template.info", "a", 402) in state["probes"]
    assert ("image.info", "a", 503) in state["probes"]
    assert ("image.clone", "a", 504) in state["probes"]
    assert ("image.delete", "a", 504, True) in state["probes"]
    assert ("secgroup.chmod", "a", 602) in state["probes"]
    assert ("vn.chmod", "a", 702) in state["probes"]


def test_opennebula_tenant_isolation_reports_real_user_ids_on_setup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant-isolation setup failures still report allocated tenant identities."""
    module = _load_security_script("tenant_isolation_test.py")

    class FakeAdminUser:
        """Fake admin-side user endpoint."""

        def allocate(self, username: str, _password: str, _auth_driver: str = "core") -> int:
            """Allocate fake tenant users."""
            return 101 if "-a-" in username else 102

        def delete(self, _user_id: int) -> None:
            """Delete fake users."""

    class FakeAdminGroup:
        """Fake admin-side group endpoint."""

        def allocate(self, _group_name: str) -> int:
            """Fail tenant setup after users exist."""
            raise RuntimeError("group allocation denied")

    admin_one = SimpleNamespace(user=FakeAdminUser(), group=FakeAdminGroup())

    def fake_get_one_server(_xmlrpc_url: str, auth: str) -> Any:
        """Return the fake admin client."""
        assert auth == "oneadmin:opennebula"
        return admin_one

    monkeypatch.setattr(module, "get_one_server", fake_get_one_server)

    payload = module.evaluate_tenant_isolation(
        region="opennebula",
        xmlrpc_url="http://one.example.internal:2633/RPC2",
        admin_auth="oneadmin:opennebula",
        datastore_id=1,
        cluster_id=-1,
    )

    assert payload["success"] is False
    assert payload["tenant_a_id"].startswith("opennebula:user/isv-ti-a-")
    assert payload["tenant_a_id"].endswith(":101")
    assert payload["tenant_b_id"].startswith("opennebula:user/isv-ti-b-")
    assert payload["tenant_b_id"].endswith(":102")
    assert "allocate group" in payload["error"]
    assert all("allocate group" in test["error"] for test in payload["tests"].values())


def test_opennebula_audit_logging_passes_with_matching_log_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """OpenNebula SEC08 checks pass when the audit log contains the emitted event."""
    module = _load_security_script("audit_logging_test.py")
    audit_log = tmp_path / "oned.log"
    audit_log.write_text("", encoding="utf-8")
    logrotate_config, logrotate_main_config = _write_logrotate_policy(
        tmp_path,
        f"{audit_log} /var/log/one/one_xmlrpc.log /var/log/one/monitor.log {{\n"
        "    dateext\n"
        "    weekly\n"
        "    rotate 52\n"
        "    compress\n"
        "}\n",
    )

    def fake_call(_xmlrpc_url: str, _auth: str, marker: str, _timeout_seconds: float) -> str:
        """Write the audit evidence that a real OpenNebula log pipeline would emit."""
        audit_log.write_text(
            ("Fri Jun  5 10:22:35 2026 [Z0][ReM][D]: Req:8368 UID:1 IP:127.0.0.1 one.system.version invoked\n"),
            encoding="utf-8",
        )
        return module.EVENT_NAME

    monkeypatch.setattr(module, "_call_management_api", fake_call)

    payload = module.evaluate_audit_logging(
        region="one",
        xmlrpc_url="http://one.example.internal:2633/RPC2",
        auth="oneadmin:secret",
        audit_log_path=audit_log,
        logrotate_config_path=logrotate_config,
        logrotate_main_config_path=logrotate_main_config,
        poll_seconds=1,
        poll_interval_seconds=0,
        xmlrpc_timeout_seconds=1,
        max_bytes=20_000,
    )

    assert payload["success"] is False
    assert payload["tests"]["audit_log_entry_found"]["passed"] is True
    assert payload["tests"]["audit_log_event_name_matches"]["passed"] is True
    assert payload["tests"]["audit_log_user_identity_present"]["passed"] is True
    assert payload["tests"]["audit_log_source_ip_present"]["passed"] is True
    assert payload["tests"]["audit_log_user_agent_matches"]["passed"] is True
    assert payload["tests"]["audit_log_region_matches"]["passed"] is True
    assert payload["tests"]["audit_log_event_source_matches"]["passed"] is True
    assert payload["tests"]["audit_log_retention_at_least_30_days"]["passed"] is False


def test_opennebula_audit_logging_fails_without_log_file() -> None:
    """OpenNebula SEC08 checks fail when audit evidence is not readable."""
    module = _load_security_script("audit_logging_test.py")
    missing_log = Path("/tmp/does-not-exist-opennebula-audit.log")

    payload = module.evaluate_audit_logging(
        region="one",
        xmlrpc_url="http://one.example.internal:2633/RPC2",
        auth="oneadmin:secret",
        audit_log_path=missing_log,
        logrotate_config_path=Path("/tmp/does-not-exist-opennebula-logrotate.conf"),
        logrotate_main_config_path=Path("/tmp/does-not-exist-logrotate.conf"),
        poll_seconds=1,
        poll_interval_seconds=0,
        xmlrpc_timeout_seconds=1,
        max_bytes=20_000,
    )

    assert payload["success"] is False
    assert payload["tests"]["audit_log_entry_found"]["passed"] is False


def test_opennebula_audit_logging_fails_short_retention(tmp_path: Path) -> None:
    """OpenNebula SEC08 retention check requires at least 30 days."""
    module = _load_security_script("audit_logging_test.py")
    audit_log = tmp_path / "oned.log"
    logrotate_config, logrotate_main_config = _write_logrotate_policy(
        tmp_path,
        f"{audit_log} {{\n    weekly\n    rotate 4\n}}\n",
    )

    tests = module._evaluate_retention_tests(
        audit_log_path=audit_log,
        logrotate_config_path=logrotate_config,
        logrotate_main_config_path=logrotate_main_config,
    )

    assert tests["audit_log_trail_logging_enabled"]["passed"] is True
    assert tests["audit_log_retention_at_least_30_days"]["passed"] is False


def test_opennebula_audit_logging_fails_weekly_rotate_52_retention(tmp_path: Path) -> None:
    """OpenNebula SEC08 retention does not accept logrotate-only evidence."""
    module = _load_security_script("audit_logging_test.py")
    audit_log = tmp_path / "one_xmlrpc.log"
    logrotate_config, logrotate_main_config = _write_logrotate_policy(
        tmp_path,
        f"{audit_log} /var/log/one/oned.log /var/log/one/monitor.log {{\n"
        "    dateext\n"
        "    dateformat -%Y%m%d-%s\n"
        "    weekly\n"
        "    rotate 52\n"
        "    missingok\n"
        "    notifempty\n"
        "    copytruncate\n"
        "    compress\n"
        "    compressoptions -9\n"
        "    delaycompress\n"
        "}\n",
    )

    tests = module._evaluate_retention_tests(
        audit_log_path=audit_log,
        logrotate_config_path=logrotate_config,
        logrotate_main_config_path=logrotate_main_config,
    )

    assert tests["audit_log_trail_logging_enabled"]["passed"] is True
    assert tests["audit_log_retention_at_least_30_days"]["passed"] is False
    probes = tests["audit_log_retention_at_least_30_days"]["probes"][0]
    assert probes["computed_retention_days"] == 364


def test_opennebula_audit_logging_fails_when_logrotate_not_included(tmp_path: Path) -> None:
    """OpenNebula SEC08 retention requires logrotate.conf to include the policy."""
    module = _load_security_script("audit_logging_test.py")
    audit_log = tmp_path / "oned.log"
    config_dir = tmp_path / "logrotate.d"
    config_dir.mkdir()
    logrotate_config = config_dir / "opennebula"
    logrotate_config.write_text(f"{audit_log} {{\n    weekly\n    rotate 52\n}}\n", encoding="utf-8")
    logrotate_main_config = tmp_path / "logrotate.conf"
    logrotate_main_config.write_text("weekly\n", encoding="utf-8")

    tests = module._evaluate_retention_tests(
        audit_log_path=audit_log,
        logrotate_config_path=logrotate_config,
        logrotate_main_config_path=logrotate_main_config,
    )

    assert tests["audit_log_trail_logging_enabled"]["passed"] is False
    assert tests["audit_log_retention_at_least_30_days"]["passed"] is False
