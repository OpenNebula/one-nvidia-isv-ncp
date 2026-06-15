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

"""Bare metal NVIDIA driver validations."""

from typing import ClassVar

import pytest

from isvtest.core.nvidia import compare_versions, parse_driver_version
from isvtest.core.ssh import get_ssh_client, get_ssh_config, run_ssh_command, ssh_auth_available
from isvtest.core.validation import BaseValidation


def run_guest_or_local_command(validation: BaseValidation, command: str) -> tuple[int, str, str]:
    """Run a BM command over SSH when host inventory exists, otherwise locally."""
    inventory = validation.config.get("inventory", {})
    ssh_cfg = get_ssh_config(validation.config, inventory)
    host = ssh_cfg["ssh_host"]
    key_path = ssh_cfg["ssh_key_path"]

    if host and ssh_auth_available(key_path, validation.config, inventory):
        ssh = get_ssh_client(
            host,
            ssh_cfg["ssh_user"],
            key_path,
            config=validation.config,
            inventory=inventory,
        )
        try:
            return run_ssh_command(ssh, command, timeout=validation.timeout)
        finally:
            ssh.close()

    result = validation.run_command(command)
    if result.exit_code != 0 and "nvidia-smi" in command and "not found" in result.stderr.lower():
        pytest.skip("nvidia-smi not available on local runner")
    return result.exit_code, result.stdout, result.stderr


class BmDriverInstalled(BaseValidation):
    """Verify NVIDIA driver is installed and loaded."""

    description: ClassVar[str] = "Verify NVIDIA driver is installed and accessible via nvidia-smi"
    timeout: ClassVar[int] = 30
    labels: ClassVar[tuple[str, ...]] = ("bare_metal",)

    def run(self) -> None:
        exit_code, _stdout, stderr = run_guest_or_local_command(self, "nvidia-smi")

        if exit_code != 0:
            self.set_failed(f"nvidia-smi failed: {stderr}")
            return

        self.set_passed("NVIDIA driver is installed and working")


class BmDriverVersion(BaseValidation):
    """Verify NVIDIA driver version can be queried and meets minimum requirements."""

    description: ClassVar[str] = "Query NVIDIA driver version and validate format"
    timeout: ClassVar[int] = 30
    labels: ClassVar[tuple[str, ...]] = ("bare_metal",)

    def run(self) -> None:
        exit_code, stdout, stderr = run_guest_or_local_command(
            self, "nvidia-smi --query-gpu=driver_version --format=csv,noheader"
        )

        if exit_code != 0:
            self.set_failed(f"Failed to query driver version: {stderr}")
            return

        # Parse driver version using shared parser
        version = parse_driver_version(stdout)
        if not version:
            self.set_failed("Driver version is empty or invalid")
            return

        # Validate version format (should have at least major.minor)
        version_parts = version.split(".")
        if len(version_parts) < 2:
            self.set_failed(f"Invalid driver version format: {version}")
            return

        # Check against minimum version if configured
        min_version = self.config.get("min_version")
        if min_version:
            if not compare_versions(version, min_version):
                self.set_failed(f"Driver version {version} is below minimum required {min_version}")
                return

        self.set_passed(f"Driver version: {version}")
