#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Emit explicit failure for OpenNebula service-account credential validation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

TEST_NAME = "sa_credential_test"
NOT_IMPLEMENTED_MESSAGE = (
    "Not implemented - OpenNebula service users are internal platform users; "
    "no first-class external service-account credential model is exposed by the documented user-token API"
)


def build_result(*, region: str) -> dict[str, Any]:
    """Build provider-neutral failure output for unsupported OpenNebula service accounts."""
    return {
        "success": False,
        "platform": "security",
        "test_name": TEST_NAME,
        "region": region,
        "authenticated": False,
        "credential_type": "opennebula_internal_service_user",
        "identity": "",
        "expires_at": None,
        "error": NOT_IMPLEMENTED_MESSAGE,
    }


def main() -> int:
    """Emit OpenNebula service-account unsupported result JSON."""
    parser = argparse.ArgumentParser(description="OpenNebula service-account credential test")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--xmlrpc-url", default=os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"))
    parser.add_argument("--auth", default=os.environ.get("ONE_AUTH", "oneadmin:opennebula"))
    parser.add_argument("--token-ttl-seconds", type=int, default=int(os.environ.get("ONE_SERVICE_ACCOUNT_TOKEN_TTL_SECONDS", "-1")))
    args = parser.parse_args()

    print(json.dumps(build_result(region=args.region), indent=2))
    return 1


if __name__ == "__main__":
    sys.exit(main())
