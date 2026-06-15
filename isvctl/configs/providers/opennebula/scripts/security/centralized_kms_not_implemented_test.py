#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Emit explicit failure for unimplemented OpenNebula centralized KMS validation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

TEST_NAME = "centralized_kms_test"
TEST_KEYS = [
    "kms_service_reachable",
    "kms_keys_present",
    "all_encrypted_resources_use_kms",
]
NOT_IMPLEMENTED_MESSAGE = "Not implemented - OpenNebula centralized KMS validation is not implemented"


def build_result(*, region: str) -> dict[str, Any]:
    """Build provider-neutral failure output for unimplemented centralized KMS validation."""
    return {
        "success": False,
        "platform": "security",
        "test_name": TEST_NAME,
        "region": region,
        "error": NOT_IMPLEMENTED_MESSAGE,
        "kms_keys_total": 0,
        "encrypted_resources_inspected": 0,
        "non_kms_resources": 0,
        "tests": {
            key: {
                "passed": False,
                "error": f"{key}: {NOT_IMPLEMENTED_MESSAGE} in region {region}",
            }
            for key in TEST_KEYS
        },
    }


def main() -> int:
    """Emit unimplemented centralized KMS result JSON."""
    parser = argparse.ArgumentParser(description="OpenNebula centralized KMS not-implemented result")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    args = parser.parse_args()

    print(json.dumps(build_result(region=args.region), indent=2))
    return 1


if __name__ == "__main__":
    sys.exit(main())
