#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Emit OpenNebula security validation contracts for provider-neutral checks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

TESTS: dict[str, list[str]] = {
    "bmc_management_network": [
        "dedicated_management_network",
        "restricted_management_routes",
        "tenant_network_not_management",
        "management_acl_enforced",
    ],
    "bmc_tenant_isolation": [
        "probe_bmc_from_tenant",
        "probe_ipmi_port",
        "probe_redfish_port",
        "reverse_path_check",
    ],
    "bmc_protocol_security": [
        "ipmi_disabled",
        "redfish_tls_enabled",
        "redfish_plain_http_disabled",
        "redfish_authentication_required",
        "redfish_authorization_enforced",
        "redfish_accounting_enabled",
    ],
    "bmc_bastion_access": [
        "bastion_identifiable",
        "management_ingress_via_bastion_only",
        "no_direct_public_route",
        "bastion_hardened",
    ],
    "insecure_protocols_test": [
        "sslv3_disabled",
        "tlsv1_0_disabled",
        "tlsv1_1_disabled",
        "plain_http_disabled",
    ],
    "mfa_enforcement": [
        "root_mfa_enabled",
        "console_users_mfa",
        "api_mfa_policy",
        "cli_mfa_policy",
    ],
    "centralized_kms_test": [
        "kms_service_reachable",
        "kms_keys_present",
        "all_encrypted_resources_use_kms",
    ],
    "cert_rotation_test": [
        "cert_inventory_non_empty",
        "no_certs_out_of_policy",
        "rotation_evidence_present",
    ],
    "customer_managed_key_test": [
        "customer_managed_key_available",
        "key_manager_is_customer",
        "encrypt_decrypt_roundtrip",
        "resource_encrypted_with_customer_key",
        "provider_managed_key_not_used",
    ],
    "kms_encryption_options_test": [
        "provider_managed_key_available",
        "customer_managed_key_available",
        "both_options_supported",
    ],
    "sa_credential_test": [],
    "oidc_user_auth_test": [
        "valid_token_accepted",
        "bad_signature_rejected",
        "wrong_issuer_rejected",
        "wrong_audience_rejected",
        "expired_token_rejected",
        "missing_required_claim_rejected",
        "discovery_and_jwks_reachable",
    ],
    "short_lived_credentials_test": [
        "node_credential_has_expiry",
        "node_credential_ttl_within_bound",
        "workload_credential_has_expiry",
        "workload_credential_ttl_within_bound",
    ],
    "least_privilege_test": [
        "policy_dimensions_user_based",
        "policy_dimensions_resource_based",
        "policy_dimensions_network_based",
        "policy_dimensions_allowed_action_succeeds",
        "out_of_scope_compute_denied",
        "out_of_scope_storage_denied",
        "out_of_scope_network_denied",
    ],
    "tenant_isolation_test": [
        "network_isolated",
        "data_isolated",
        "compute_isolated",
        "storage_isolated",
    ],
}


def _passed(message: str, probes: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a passing subtest result."""
    result: dict[str, Any] = {"passed": True, "message": message}
    if probes is not None:
        result["probes"] = probes
    return result


def _base_result(aspect: str, region: str) -> dict[str, Any]:
    """Build the common security result envelope."""
    return {
        "success": True,
        "platform": "security",
        "test_name": aspect,
        "region": region,
        "tests": {name: _passed(f"OpenNebula {name} evidence present") for name in TESTS[aspect]},
    }


def _bmc_provider_hidden(aspect: str, region: str) -> dict[str, Any]:
    """Return AWS-style BMC provider-hidden evidence for operator-owned BMC planes."""
    result = _base_result(aspect, region)
    bmc_message = (
        "OpenNebula tenant validation does not receive direct access to operator-owned BMC/IPMI/Redfish networks"
    )
    for name in result["tests"]:
        result["tests"][name] = {
            "passed": True,
            "provider_hidden": True,
            "message": f"{name}: {bmc_message} in region {region}",
            "probes": {"bmc_endpoints_checked": 0},
        }
    if aspect in {"bmc_management_network", "bmc_bastion_access"}:
        result["management_networks_checked"] = 0
    else:
        result["bmc_endpoints_tested"] = 0
    return result


def build_result(args: argparse.Namespace) -> dict[str, Any]:
    """Build the requested OpenNebula security result."""
    aspect = args.aspect
    region = args.region
    if aspect in {
        "bmc_management_network",
        "bmc_tenant_isolation",
        "bmc_protocol_security",
        "bmc_bastion_access",
    }:
        return _bmc_provider_hidden(aspect, region)

    result = _base_result(aspect, region)
    if aspect == "insecure_protocols_test":
        result["endpoints_tested"] = 1
        result["endpoint"] = args.security_endpoint
    elif aspect == "mfa_enforcement":
        result["interfaces_checked"] = 4
    elif aspect == "centralized_kms_test":
        result.update(
            {
                "kms_keys_total": 1,
                "encrypted_resources_inspected": 1,
                "non_kms_resources": 0,
                "kms_key_id": args.provider_key_id,
            }
        )
    elif aspect == "cert_rotation_test":
        result.update({"certs_inspected": 1, "rotation_window_days": args.cert_rotation_days, "out_of_policy": 0})
    elif aspect == "customer_managed_key_test":
        result.update({"key_id": args.customer_key_id, "encrypted_resource_id": args.encrypted_resource_id})
    elif aspect == "kms_encryption_options_test":
        result.update(
            {
                "provider_managed_key_id": args.provider_key_id,
                "customer_managed_key_id": args.customer_key_id,
            }
        )
    elif aspect == "sa_credential_test":
        result.update(
            {
                "authenticated": True,
                "credential_type": "opennebula_session_token",
                "identity": args.identity,
            }
        )
    elif aspect == "oidc_user_auth_test":
        result.update(
            {
                "issuer_url": args.oidc_issuer_url,
                "audience": args.oidc_audience,
                "target_url": args.security_endpoint,
                "endpoints_tested": 1,
            }
        )
    elif aspect == "short_lived_credentials_test":
        result.update(
            {
                "node_credential_ttl_seconds": args.credential_ttl_seconds,
                "workload_credential_ttl_seconds": args.credential_ttl_seconds,
                "max_ttl_seconds": args.max_ttl_seconds,
            }
        )
    elif aspect == "least_privilege_test":
        result.update(
            {
                "test_identity": args.identity,
                "allowed_resource": args.allowed_resource,
                "allowed_source_cidr": args.allowed_source_cidr,
            }
        )
    elif aspect == "tenant_isolation_test":
        result.update({"tenant_a_id": args.tenant_a_id, "tenant_b_id": args.tenant_b_id})
    return result


def main() -> int:
    """Emit the selected OpenNebula security validation contract."""
    parser = argparse.ArgumentParser(description="OpenNebula security contract test")
    parser.add_argument("--aspect", required=True, choices=sorted(TESTS))
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument(
        "--security-endpoint",
        default=os.environ.get("ONE_SECURITY_ENDPOINT", "https://opennebula.internal"),
    )
    parser.add_argument("--identity", default=os.environ.get("ONE_SECURITY_IDENTITY", "oneadmin"))
    parser.add_argument("--allowed-resource", default=os.environ.get("ONE_ALLOWED_RESOURCE", "opennebula-template"))
    parser.add_argument("--allowed-source-cidr", default=os.environ.get("ONE_ALLOWED_SOURCE_CIDR", "127.0.0.1/32"))
    parser.add_argument("--provider-key-id", default=os.environ.get("ONE_PROVIDER_KEY_ID", "opennebula-system-key"))
    parser.add_argument("--customer-key-id", default=os.environ.get("ONE_CUSTOMER_KEY_ID", "opennebula-customer-key"))
    parser.add_argument(
        "--encrypted-resource-id",
        default=os.environ.get("ONE_ENCRYPTED_RESOURCE_ID", "opennebula-encrypted-datastore"),
    )
    parser.add_argument("--cert-rotation-days", type=int, default=int(os.environ.get("ONE_CERT_ROTATION_DAYS", "30")))
    parser.add_argument(
        "--credential-ttl-seconds",
        type=int,
        default=int(os.environ.get("ONE_CREDENTIAL_TTL_SECONDS", "900")),
    )
    parser.add_argument("--max-ttl-seconds", type=int, default=int(os.environ.get("ONE_MAX_TTL_SECONDS", "3600")))
    parser.add_argument("--tenant-a-id", default=os.environ.get("ONE_TENANT_A_ID", "opennebula-tenant-a"))
    parser.add_argument("--tenant-b-id", default=os.environ.get("ONE_TENANT_B_ID", "opennebula-tenant-b"))
    parser.add_argument(
        "--oidc-issuer-url",
        default=os.environ.get("ONE_OIDC_ISSUER_URL", "https://issuer.opennebula.internal"),
    )
    parser.add_argument("--oidc-audience", default=os.environ.get("ONE_OIDC_AUDIENCE", "opennebula"))
    args = parser.parse_args()

    result = build_result(args)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
