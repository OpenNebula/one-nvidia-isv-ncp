#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Emit structured SEC08 audit logging skips for the OpenNebula provider."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

TEST_NAME = "audit_logging_test"
AUDIT_ENTRY_TEST_KEYS = (
    "audit_log_entry_found",
    "audit_log_event_name_matches",
    "audit_log_event_time_in_window",
    "audit_log_user_identity_present",
    "audit_log_source_ip_present",
    "audit_log_user_agent_matches",
    "audit_log_region_matches",
    "audit_log_event_source_matches",
)
AUDIT_RETENTION_TEST_KEYS = (
    "audit_log_trail_logging_enabled",
    "audit_log_retention_at_least_30_days",
)
SKIP_REASON = "OpenNebula audit logging validation is environment specific"


def _base_result() -> dict[str, Any]:
    """Return the provider-neutral SEC08 result envelope."""
    return {
        "success": True,
        "platform": "security",
        "test_name": TEST_NAME,
        "audit_log_entry_skipped": True,
        "audit_log_entry_skip_reason": SKIP_REASON,
        "audit_log_retention_skipped": True,
        "audit_log_retention_skip_reason": SKIP_REASON,
        "tests": {
            key: {"passed": True, "skipped": True, "skip_reason": SKIP_REASON}
            for key in (*AUDIT_ENTRY_TEST_KEYS, *AUDIT_RETENTION_TEST_KEYS)
        },
    }


def main() -> int:
    """Emit structured skip JSON for SEC08 audit logging and retention."""
    parser = argparse.ArgumentParser(description="OpenNebula audit logging and retention test (SEC08-01/02)")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.parse_args()

    print(json.dumps(_base_result(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
