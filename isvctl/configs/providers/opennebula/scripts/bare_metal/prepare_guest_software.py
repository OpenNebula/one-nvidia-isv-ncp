#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Prepare OpenNebula/NICo bare-metal guest software for GPU validations."""

import argparse
import json
import sys
import time
from typing import Any

from deploy_nim import (
    NicoAPI,
    api_reboot_instance,
    resolve_instance,
    ssh_run,
    wait_for_nico_reboot,
    wait_for_ssh,
)


def ensure_docker(host: str) -> None:
    """Install and start Docker if the guest image does not include it."""
    exit_code, _stdout, _stderr = ssh_run(host, "command -v docker >/dev/null 2>&1", 30)
    if exit_code != 0:
        install_cmd = (
            "sudo apt-get update && "
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io && "
            "(sudo systemctl enable --now docker || sudo service docker start)"
        )
        exit_code, stdout, stderr = ssh_run(host, install_cmd, 600)
        if exit_code != 0:
            raise RuntimeError(f"Docker installation failed: {stderr.strip() or stdout.strip()}")

    exit_code, stdout, stderr = ssh_run(host, "sudo usermod -aG docker ubuntu && docker --version", 60)
    if exit_code != 0:
        raise RuntimeError(f"Docker user setup failed: {stderr.strip() or stdout.strip()}")

    exit_code, stdout, stderr = ssh_run(host, "docker info >/dev/null", 60)
    if exit_code == 0:
        return

    # Group membership should apply on new SSH sessions. Fall back to a socket ACL
    # only for validation images that do not refresh supplementary groups promptly.
    exit_code, stdout, stderr = ssh_run(host, "sudo chmod 666 /var/run/docker.sock && docker info >/dev/null", 60)
    if exit_code != 0:
        raise RuntimeError(f"Docker is not usable by ubuntu: {stderr.strip() or stdout.strip()}")


def ensure_host_nvidia_driver(
    instance_id: int,
    deploy_id: str,
    host: str,
    api_timeout: int,
    reboot_timeout: int,
    ssh_wait_timeout: int,
) -> None:
    """Install NVIDIA driver/CUDA toolkit if the guest image does not include it."""
    exit_code, stdout, stderr = ssh_run(host, "nvidia-smi", 60)
    if exit_code == 0:
        return

    detect_cmd = ". /etc/os-release && printf '%s %s' \"$VERSION_ID\" \"$(dpkg --print-architecture)\""
    exit_code, stdout, stderr = ssh_run(host, detect_cmd, 30)
    if exit_code != 0:
        raise RuntimeError(f"Could not detect Ubuntu version/architecture: {stderr.strip() or stdout.strip()}")

    version_id, deb_arch = stdout.strip().split(maxsplit=1)
    ubuntu_version = version_id.replace(".", "")
    cuda_arch = "sbsa" if deb_arch == "arm64" else "x86_64"
    cuda_repo = f"https://developer.download.nvidia.com/compute/cuda/repos/ubuntu{ubuntu_version}/{cuda_arch}"

    install_cmd = " && ".join(
        [
            "sudo apt-get update",
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y linux-headers-$(uname -r) wget ca-certificates gnupg",
            f"cd /tmp && wget -q {cuda_repo}/cuda-keyring_1.1-1_all.deb -O cuda-keyring_1.1-1_all.deb",
            "sudo dpkg -i /tmp/cuda-keyring_1.1-1_all.deb",
            "sudo apt-get update",
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y cuda-toolkit-13-0 nvidia-open",
            "sudo systemctl enable nvidia-persistenced || true",
        ]
    )
    exit_code, stdout, stderr = ssh_run(host, install_cmd, 1800)
    if exit_code != 0:
        raise RuntimeError(f"NVIDIA driver installation failed: {stderr.strip() or stdout.strip()}")

    api = NicoAPI(api_timeout)
    api_reboot_instance(instance_id)
    wait_for_nico_reboot(api, deploy_id, reboot_timeout)
    wait_for_ssh(host, timeout=ssh_wait_timeout)

    deadline = time.time() + 900
    last_output = ""
    while time.time() < deadline:
        exit_code, stdout, stderr = ssh_run(host, "nvidia-smi", 60)
        last_output = (stderr or stdout).strip()
        if exit_code == 0:
            return
        time.sleep(15)

    raise RuntimeError(f"nvidia-smi did not become ready after driver installation: {last_output}")


def ensure_nvidia_container_runtime(host: str) -> None:
    """Install/configure NVIDIA Container Toolkit for Docker GPU access."""
    exit_code, _stdout, _stderr = ssh_run(
        host, "sudo docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi >/dev/null 2>&1", 300
    )
    if exit_code == 0:
        return

    install_cmd = " && ".join(
        [
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates gnupg",
            "curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | "
            "sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg",
            "curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | "
            "sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | "
            "sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null",
            "sudo apt-get update",
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nvidia-container-toolkit",
            "sudo nvidia-ctk runtime configure --runtime=docker",
            "sudo systemctl restart docker || sudo service docker restart",
        ]
    )
    exit_code, stdout, stderr = ssh_run(host, install_cmd, 900)
    if exit_code != 0:
        raise RuntimeError(f"NVIDIA Container Toolkit installation failed: {stderr.strip() or stdout.strip()}")

    exit_code, stdout, stderr = ssh_run(host, "docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi", 300)
    if exit_code != 0:
        raise RuntimeError(f"Docker GPU runtime check failed: {stderr.strip() or stdout.strip()}")


def ensure_infiniband_tools(host: str) -> None:
    """Install RDMA/InfiniBand userspace tools used by validations."""
    exit_code, _stdout, _stderr = ssh_run(
        host,
        "command -v ibstat >/dev/null 2>&1 && command -v ibv_devinfo >/dev/null 2>&1 && command -v rdma >/dev/null 2>&1",
        30,
    )
    if exit_code == 0:
        return

    install_cmd = (
        "sudo apt-get update && "
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y infiniband-diags rdma-core ibverbs-utils"
    )
    exit_code, stdout, stderr = ssh_run(host, install_cmd, 600)
    if exit_code != 0:
        raise RuntimeError(f"InfiniBand/RDMA tools installation failed: {stderr.strip() or stdout.strip()}")

    exit_code, stdout, stderr = ssh_run(host, "command -v ibstat && command -v ibv_devinfo && command -v rdma", 30)
    if exit_code != 0:
        raise RuntimeError(f"InfiniBand/RDMA tools are not available after installation: {stderr.strip() or stdout.strip()}")


def prune_container_storage(host: str) -> None:
    """Remove unused Docker/containerd data before large workload image pulls."""
    cleanup_cmd = "sudo docker system prune -af --volumes && sudo docker builder prune -af && sudo apt-get clean"
    exit_code, stdout, stderr = ssh_run(host, cleanup_cmd, 600)
    if exit_code != 0:
        raise RuntimeError(f"Container storage pruning failed: {stderr.strip() or stdout.strip()}")


def probe(host: str, name: str, command: str, timeout: int) -> dict[str, Any]:
    """Run a guest probe and return compact structured evidence."""
    exit_code, stdout, stderr = ssh_run(host, command, timeout)
    output = (stdout or stderr).strip()
    return {
        "passed": exit_code == 0,
        "message": output.splitlines()[0][:200] if output else name,
        "probes": [name],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare OpenNebula BM guest GPU/container software")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--api-timeout", type=int, default=60, help="NICo API request timeout")
    parser.add_argument("--nico-reboot-timeout", type=int, default=1800, help="Seconds to wait for NICo reboot recovery")
    parser.add_argument("--ssh-wait-timeout", type=int, default=1800, help="Seconds to wait for SSH readiness")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "test_name": "prepare_guest_software",
        "instance_id": str(args.instance_id),
        "ssh_user": "ubuntu",
        "tests": {},
    }

    try:
        deploy_id, host = resolve_instance(args.instance_id, args.api_timeout)
        result.update({"deploy_id": deploy_id, "nico_instance_id": deploy_id, "host": host, "public_ip": host, "private_ip": host})

        wait_for_ssh(host, args.ssh_wait_timeout)
        result["tests"]["ssh"] = probe(host, "ssh", "true", 30)

        ensure_host_nvidia_driver(
            args.instance_id,
            deploy_id,
            host,
            args.api_timeout,
            args.nico_reboot_timeout,
            args.ssh_wait_timeout,
        )
        result["tests"]["nvidia_driver"] = probe(host, "nvidia-smi", "nvidia-smi", 60)

        ensure_docker(host)
        result["tests"]["docker"] = probe(host, "docker", "docker --version", 60)

        ensure_nvidia_container_runtime(host)
        result["tests"]["nvidia_container_runtime"] = probe(
            host,
            "docker_gpu_runtime",
            "docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi",
            300,
        )

        ensure_infiniband_tools(host)
        result["tests"]["infiniband_tools"] = probe(
            host,
            "infiniband_tools",
            "command -v ibstat && command -v ibv_devinfo && command -v rdma",
            30,
        )

        prune_container_storage(host)
        result["tests"]["container_storage_prune"] = probe(host, "container_storage_prune", "docker system df", 30)

        result["success"] = all(test.get("passed", False) for test in result["tests"].values())
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
