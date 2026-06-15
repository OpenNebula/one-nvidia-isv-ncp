#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Sample recent host logs from an OpenNebula/NICo bare-metal instance."""

import argparse
import json
import sys
import time
from typing import Any

from deploy_nim import resolve_instance, ssh_run, wait_for_ssh


def source_result(passed: bool, message: str, sample: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {"passed": passed, "message": message}
    if sample:
        result["sample"] = sample[-2000:]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Sample recent BM host status logs")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--api-timeout", type=int, default=60, help="NICo API request timeout")
    parser.add_argument("--ssh-wait-timeout", type=int, default=60, help="Seconds to wait for SSH readiness")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "instance_id": str(args.instance_id),
        "test_name": "host_status_log",
        "tests": {},
    }

    try:
        deploy_id, host = resolve_instance(args.instance_id, args.api_timeout)
        result.update({"deploy_id": deploy_id, "nico_instance_id": deploy_id, "host": host, "public_ip": host})
        wait_for_ssh(host, args.ssh_wait_timeout)

        exit_code, stdout, stderr = ssh_run(host, "journalctl --since '10 minutes ago' -n 50 --no-pager 2>&1", 60)
        output = stdout or stderr
        result["tests"]["journalctl_recent"] = source_result(
            exit_code == 0 and bool(output.strip()),
            "journalctl returned recent entries" if exit_code == 0 and output.strip() else "journalctl had no recent entries",
            output,
        )

        exit_code, stdout, stderr = ssh_run(host, "dmesg --ctime 2>/dev/null | tail -50", 60)
        output = stdout or stderr
        result["tests"]["dmesg_recent"] = source_result(
            exit_code == 0 and bool(output.strip()),
            "dmesg returned entries" if exit_code == 0 and output.strip() else "dmesg had no entries",
            output,
        )

        exit_code, stdout, stderr = ssh_run(host, "systemctl is-system-running 2>&1 || true", 30)
        output = (stdout or stderr).strip()
        result["tests"]["system_status"] = source_result(
            bool(output),
            f"systemctl is-system-running: {output or 'unknown'}",
            output,
        )

        result["timestamp"] = int(time.time())
        result["success"] = any(test.get("passed") for test in result["tests"].values())
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
