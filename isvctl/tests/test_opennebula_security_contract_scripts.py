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

"""Tests for OpenNebula security contract scripts."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace

from isvtest.validations.iam import ServiceAccountCredentialCheck
from isvtest.validations.security import (
    BmcManagementNetworkCheck,
    CentralizedKmsCheck,
    InsecureProtocolsCheck,
    LeastPrivilegePolicyCheck,
    MinimalRoleEnforcementCheck,
    OidcUserAuthCheck,
    ShortLivedCredentialsCheck,
    TenantIsolationCheck,
)

ISVCTL_ROOT = Path(__file__).resolve().parents[1]
OPENNEBULA_SECURITY_SCRIPTS = ISVCTL_ROOT / "configs" / "providers" / "opennebula" / "scripts" / "security"


def _load_script(script_name: str) -> ModuleType:
    """Load an OpenNebula security script as a module."""
    script_path = OPENNEBULA_SECURITY_SCRIPTS / script_name
    spec = importlib.util.spec_from_file_location(f"test_opennebula_{script_path.stem}", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _args(aspect: str) -> SimpleNamespace:
    """Return default CLI-equivalent arguments for contract generation."""
    return SimpleNamespace(
        aspect=aspect,
        region="opennebula",
        security_endpoint="https://opennebula.internal",
        identity="oneadmin",
        allowed_resource="opennebula-template",
        allowed_source_cidr="127.0.0.1/32",
        provider_key_id="opennebula-system-key",
        customer_key_id="opennebula-customer-key",
        encrypted_resource_id="opennebula-encrypted-datastore",
        cert_rotation_days=30,
        credential_ttl_seconds=900,
        max_ttl_seconds=3600,
        tenant_a_id="tenant-a",
        tenant_b_id="tenant-b",
        oidc_issuer_url="https://issuer.opennebula.internal",
        oidc_audience="opennebula",
    )


def _assert_validation_passes(validation_cls: type, step_output: dict[str, object]) -> None:
    """Run a validation class against step output and assert it passes."""
    validation = validation_cls(config={"step_output": step_output})
    validation.run()
    assert validation.passed, validation.message


def test_opennebula_bmc_management_contract_validates() -> None:
    """BMC management-network provider-hidden evidence satisfies the validation contract."""
    script = _load_script("security_contract_test.py")
    payload = script.build_result(_args("bmc_management_network"))

    _assert_validation_passes(BmcManagementNetworkCheck, payload)


def test_opennebula_kms_and_protocol_contracts_validate() -> None:
    """KMS and insecure protocol outputs include the required evidence fields."""
    script = _load_script("security_contract_test.py")

    _assert_validation_passes(CentralizedKmsCheck, script.build_result(_args("centralized_kms_test")))
    _assert_validation_passes(InsecureProtocolsCheck, script.build_result(_args("insecure_protocols_test")))


def test_opennebula_identity_contracts_validate() -> None:
    """Service account, OIDC, and short-lived credential outputs validate."""
    script = _load_script("security_contract_test.py")

    _assert_validation_passes(ServiceAccountCredentialCheck, script.build_result(_args("sa_credential_test")))
    _assert_validation_passes(OidcUserAuthCheck, script.build_result(_args("oidc_user_auth_test")))
    _assert_validation_passes(
        ShortLivedCredentialsCheck,
        script.build_result(_args("short_lived_credentials_test")),
    )


def test_opennebula_least_privilege_step_satisfies_both_validations() -> None:
    """The shared least-privilege step satisfies both SEC04 validation classes."""
    script = _load_script("security_contract_test.py")
    payload = script.build_result(_args("least_privilege_test"))

    _assert_validation_passes(LeastPrivilegePolicyCheck, payload)
    _assert_validation_passes(MinimalRoleEnforcementCheck, payload)


def test_opennebula_tenant_isolation_contract_validates() -> None:
    """Tenant isolation output includes tenant IDs and all four isolation surfaces."""
    script = _load_script("security_contract_test.py")
    payload = script.build_result(_args("tenant_isolation_test"))

    _assert_validation_passes(TenantIsolationCheck, payload)
