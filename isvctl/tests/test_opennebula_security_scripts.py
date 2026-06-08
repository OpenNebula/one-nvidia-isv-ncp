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
    for subtest in payload["tests"].values():
        assert subtest["passed"] is False
        assert "Not implemented" in subtest["error"]


def test_opennebula_service_account_authenticates_with_generated_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """OpenNebula service-account check creates a token, authenticates with it, and cleans up."""
    module = _load_security_script("sa_credential_test.py")
    state: dict[str, Any] = {"deleted": [], "service_auth": ""}

    class FakeAdminUser:
        """Fake admin-side user XML-RPC endpoint."""

        def allocate(self, username: str, _password: str, _auth_driver: str = "core") -> int:
            """Allocate a fake user."""
            state["username"] = username
            return 42

        def login(self, username: str, token: str, ttl_seconds: int, egid: int = -1) -> str:
            """Return a generated OpenNebula token."""
            assert username == state["username"]
            assert token == ""
            assert ttl_seconds == -1
            assert egid == -1
            return "generated-token"

        def delete(self, user_id: int) -> None:
            """Delete a fake user."""
            state["deleted"].append(user_id)

    class FakeServiceUser:
        """Fake service-account user XML-RPC endpoint."""

        def info(self, user_id: int) -> SimpleNamespace:
            """Return authenticated user info."""
            assert user_id == -1
            return SimpleNamespace(NAME=state["username"], ID="42")

    admin_one = SimpleNamespace(user=FakeAdminUser())
    service_one = SimpleNamespace(user=FakeServiceUser())

    def fake_get_one_server(_xmlrpc_url: str, auth: str) -> Any:
        """Return admin or service fake clients by auth session."""
        if auth == "oneadmin:opennebula":
            return admin_one
        state["service_auth"] = auth
        return service_one

    monkeypatch.setattr(module, "get_one_server", fake_get_one_server)

    payload = module.evaluate_service_account(
        region="opennebula",
        xmlrpc_url="http://one.example.internal:2633/RPC2",
        admin_auth="oneadmin:opennebula",
        token_ttl_seconds=-1,
    )

    assert payload["success"] is True
    assert payload["authenticated"] is True
    assert payload["credential_type"] == "opennebula_auth_token"
    assert payload["identity"].startswith("opennebula:user/isv-sa-")
    assert payload["identity"].endswith(":42")
    assert payload["expires_at"] is None
    assert state["service_auth"] == f"{state['username']}:generated-token"
    assert state["deleted"] == [42]


def test_opennebula_least_privilege_uses_real_permissions_and_fails_network_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OpenNebula least-privilege check exercises permissions and reports missing source-CIDR scope."""
    module = _load_security_script("least_privilege_test.py")
    state: dict[str, Any] = {
        "deleted_templates": [],
        "deleted_users": [],
        "chmod_template": None,
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
            """Return a generated OpenNebula login token."""
            assert token == ""
            assert ttl_seconds == -1
            assert egid == -1
            return f"token-{username}"

        def delete(self, user_id: int) -> None:
            """Delete fake users."""
            state["deleted_users"].append(user_id)

    class FakeAdminTemplate:
        """Fake admin-side template endpoint."""

        def chmod(self, template_id: int, mode: int) -> None:
            """Record template permissions."""
            state["chmod_template"] = (template_id, mode)

        def delete(self, template_id: int) -> None:
            """Delete fake templates."""
            state["deleted_templates"].append(template_id)

    class FakeAllowedTemplate:
        """Fake allowed-user template endpoint."""

        def allocate(self, template: str) -> int:
            """Allocate a fake VM template."""
            assert "ISVTEST" in template
            return 77

        def info(self, template_id: int) -> SimpleNamespace:
            """Allow owner reads."""
            assert template_id == 77
            return SimpleNamespace(ID=77, NAME="isv-lp-template")

    class FakeDeniedTemplate:
        """Fake denied-user template endpoint."""

        def info(self, template_id: int) -> None:
            """Deny non-owner reads."""
            assert template_id == 77
            raise RuntimeError("not authorized")

    admin_one = SimpleNamespace(user=FakeAdminUser(), template=FakeAdminTemplate())
    allowed_one = SimpleNamespace(template=FakeAllowedTemplate())
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
    assert "source-CIDR" in payload["tests"]["policy_dimensions_network_based"]["error"]
    assert state["chmod_template"] == (77, 600)
    assert state["deleted_templates"] == [77]
    assert state["deleted_users"] == [41, 42]


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
            (
                "Fri Jun  5 10:22:35 2026 [Z0][ReM][D]: "
                "Req:8368 UID:1 IP:127.0.0.1 one.system.version invoked\n"
            ),
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

    assert payload["success"] is True
    assert payload["tests"]["audit_log_entry_found"]["passed"] is True
    assert payload["tests"]["audit_log_event_name_matches"]["passed"] is True
    assert payload["tests"]["audit_log_user_identity_present"]["passed"] is True
    assert payload["tests"]["audit_log_source_ip_present"]["passed"] is True
    assert payload["tests"]["audit_log_user_agent_matches"]["passed"] is True
    assert payload["tests"]["audit_log_region_matches"]["passed"] is True
    assert payload["tests"]["audit_log_event_source_matches"]["passed"] is True
    assert payload["tests"]["audit_log_retention_at_least_30_days"]["passed"] is True


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
        f"{audit_log} {{\n"
        "    weekly\n"
        "    rotate 4\n"
        "}\n",
    )

    tests = module._evaluate_retention_tests(
        audit_log_path=audit_log,
        logrotate_config_path=logrotate_config,
        logrotate_main_config_path=logrotate_main_config,
    )

    assert tests["audit_log_trail_logging_enabled"]["passed"] is True
    assert tests["audit_log_retention_at_least_30_days"]["passed"] is False


def test_opennebula_audit_logging_passes_weekly_rotate_52_retention(tmp_path: Path) -> None:
    """OpenNebula SEC08 retention accepts an active weekly rotate 52 logrotate policy."""
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
    assert tests["audit_log_retention_at_least_30_days"]["passed"] is True
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
