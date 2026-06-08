#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Emit explicit failures for unimplemented OpenNebula BMC security checks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

TEST_KEYS: dict[str, list[str]] = {
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
}

NOT_IMPLEMENTED_MESSAGE = "Not implemented - OpenNebula BMC security validation is not implemented"


def build_result(*, aspect: str, region: str) -> dict[str, Any]:
    """Build provider-neutral failure output for an unimplemented BMC security check."""
    return {
        "success": False,
        "platform": "security",
        "test_name": aspect,
        "region": region,
        "error": NOT_IMPLEMENTED_MESSAGE,
        "bmc_endpoints_tested": 0,
        "management_networks_checked": 0,
        "tests": {
            key: {
                "passed": False,
                "error": f"{key}: {NOT_IMPLEMENTED_MESSAGE} in region {region}",
                "probes": {"bmc_endpoints_checked": 0, "management_networks_checked": 0},
            }
            for key in TEST_KEYS[aspect]
        },
    }


def main() -> int:
    """Emit unimplemented BMC security result JSON."""
    parser = argparse.ArgumentParser(description="OpenNebula BMC security not-implemented result")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--aspect", required=True, choices=sorted(TEST_KEYS))
    args = parser.parse_args()

    print(json.dumps(build_result(aspect=args.aspect, region=args.region), indent=2))
    return 1


if __name__ == "__main__":
    sys.exit(main())
