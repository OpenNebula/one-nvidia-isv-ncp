#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Remove a NIM container from an OpenNebula/NICo bare-metal instance."""

import argparse
import json
import re
import shlex
import sys

from deploy_nim import resolve_instance, ssh_run

_CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def main() -> int:
    parser = argparse.ArgumentParser(description="Tear down NIM container on OpenNebula BM instance")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--container-name", default="isv-nim", help="Docker container name")
    parser.add_argument("--remove-image", action="store_true", help="Also remove the container image")
    parser.add_argument("--api-timeout", type=int, default=60, help="NICo API request timeout")
    args = parser.parse_args()

    result = {
        "success": False,
        "platform": "bm",
        "instance_id": str(args.instance_id),
        "container_removed": False,
        "image_removed": False,
        "container_name": args.container_name,
    }

    if not _CONTAINER_NAME_RE.match(args.container_name):
        result["error"] = f"Invalid container name: {args.container_name!r}"
        print(json.dumps(result, indent=2))
        return 1

    try:
        deploy_id, host = resolve_instance(args.instance_id, args.api_timeout)
        result.update({"deploy_id": deploy_id, "nico_instance_id": deploy_id, "host": host})

        image_name = ""
        if args.remove_image:
            _exit_code, stdout, _stderr = ssh_run(
                host,
                f"sudo docker inspect -f '{{{{.Config.Image}}}}' {args.container_name} 2>/dev/null",
                60,
            )
            image_name = stdout.strip()

        exit_code, stdout, stderr = ssh_run(host, f"sudo docker rm -f {args.container_name} 2>&1", 120)
        already_gone = "No such container" in stdout or "No such container" in stderr
        result["container_removed"] = exit_code == 0 or already_gone

        if args.remove_image and image_name:
            exit_code, _stdout, _stderr = ssh_run(host, f"sudo docker rmi {shlex.quote(image_name)} 2>&1", 120)
            result["image_removed"] = exit_code == 0

        result["success"] = result["container_removed"]
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
