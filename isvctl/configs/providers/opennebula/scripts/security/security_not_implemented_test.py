#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Emit explicit failures for unimplemented OpenNebula security checks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

TEST_KEYS: dict[str, list[str]] = {
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
    "insecure_protocols_test": [
        "sslv3_disabled",
        "tlsv1_0_disabled",
        "tlsv1_1_disabled",
        "plain_http_disabled",
    ],
    "kms_encryption_options_test": [
        "provider_managed_key_available",
        "customer_managed_key_available",
        "both_options_supported",
    ],
    "mfa_enforcement": [
        "root_mfa_enabled",
        "console_users_mfa",
        "api_mfa_policy",
        "cli_mfa_policy",
    ],
    "minimal_role_enforcement_test": [
        "out_of_scope_compute_denied",
        "out_of_scope_storage_denied",
        "out_of_scope_network_denied",
    ],
    "oidc_user_auth_test": [
        "valid_token_accepted",
        "bad_signature_rejected",
        "wrong_issuer_rejected",
        "wrong_audience_rejected",
        "expired_token_rejected",
        "missing_required_claim_rejected",
        "discovery_and_jwks_reachable",
    ],
    "tenant_isolation_test": [
        "network_isolated",
        "data_isolated",
        "compute_isolated",
        "storage_isolated",
    ],
}

NOT_IMPLEMENTED_MESSAGE = "Not implemented - OpenNebula security validation is not implemented"


def build_result(*, aspect: str, region: str) -> dict[str, Any]:
    """Build provider-neutral failure output for an unimplemented security check."""
    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": aspect,
        "region": region,
        "error": NOT_IMPLEMENTED_MESSAGE,
        "tests": {
            key: {
                "passed": False,
                "error": f"{key}: {NOT_IMPLEMENTED_MESSAGE} in region {region}",
            }
            for key in TEST_KEYS[aspect]
        },
    }
    if aspect == "tenant_isolation_test":
        result["tenant_a_id"] = "opennebula-tenant-a"
        result["tenant_b_id"] = "opennebula-tenant-b"
    return result


def main() -> int:
    """Emit unimplemented security result JSON."""
    parser = argparse.ArgumentParser(description="OpenNebula security not-implemented result")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--aspect", required=True, choices=sorted(TEST_KEYS))
    args = parser.parse_args()

    print(json.dumps(build_result(aspect=args.aspect, region=args.region), indent=2))
    return 1


if __name__ == "__main__":
    sys.exit(main())
