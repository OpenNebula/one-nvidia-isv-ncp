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

"""Tests for VM launch-with-specified-key output contracts."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from .conftest import load_vm_script

ISVCTL_ROOT = Path(__file__).resolve().parents[1]
MY_ISV_VM_SCRIPTS = ISVCTL_ROOT / "configs" / "providers" / "my-isv" / "scripts" / "vm"
OPENNEBULA_VM_SCRIPTS = ISVCTL_ROOT / "configs" / "providers" / "opennebula" / "scripts" / "vm"


def load_opennebula_vm_script(script_name: str) -> ModuleType:
    """Load an OpenNebula VM script with a fake pyone module for helper tests."""
    script_path = OPENNEBULA_VM_SCRIPTS / script_name
    spec = importlib.util.spec_from_file_location(f"test_opennebula_{script_path.stem}", script_path)
    assert spec and spec.loader

    inserted_pyone = "pyone" not in sys.modules
    if inserted_pyone:
        sys.modules["pyone"] = SimpleNamespace()

    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if inserted_pyone:
            sys.modules.pop("pyone", None)


def test_aws_launch_contract_records_matching_requested_and_actual_key() -> None:
    """Fresh AWS launch output should include requested and observed key metadata."""
    module = load_vm_script("launch_instance.py")
    result: dict[str, Any] = {
        "success": True,
        "platform": "vm",
        "instance_id": "i-abc123",
    }

    module.add_specified_key_contract(result, requested_key_name="isv-test-key", actual_key_name="isv-test-key")

    assert result["requested_key_name"] == "isv-test-key"
    assert result["key_name"] == "isv-test-key"
    assert result["tests"]["specified_key"]["passed"] is True
    assert result["tests"]["specified_key"]["probes"] == ["instance_key_name"]


def test_aws_launch_contract_flags_reuse_key_mismatch() -> None:
    """Existing-instance reuse should fail the contract when EC2 reports a different key."""
    module = load_vm_script("launch_instance.py")
    result: dict[str, Any] = {
        "success": True,
        "platform": "vm",
        "instance_id": "i-abc123",
    }

    module.add_specified_key_contract(result, requested_key_name="isv-test-key", actual_key_name="other-key")

    assert result["requested_key_name"] == "isv-test-key"
    assert result["key_name"] == "other-key"
    assert result["tests"]["specified_key"]["passed"] is False
    assert "expected key 'isv-test-key', got 'other-key'" in result["tests"]["specified_key"]["message"]


class _NoopWaiter:
    """Fake EC2 waiter."""

    def wait(self, **kwargs: Any) -> None:
        """Accept waiter calls without doing anything."""


class _FakeLaunchEc2:
    """Fake EC2 client for the fresh launch path."""

    def __init__(self) -> None:
        self.run_instances_calls: list[dict[str, Any]] = []

    def describe_images(self, **kwargs: Any) -> dict[str, Any]:
        """Return AMI details for the explicit AMI path."""
        return {"Images": [{"Name": "test-ami", "Architecture": "x86_64"}]}

    def run_instances(self, **kwargs: Any) -> dict[str, Any]:
        """Record launch kwargs and return a fake instance."""
        self.run_instances_calls.append(kwargs)
        return {"Instances": [{"InstanceId": "i-fresh"}]}

    def get_waiter(self, name: str) -> _NoopWaiter:
        """Return a fake waiter for running/status checks."""
        return _NoopWaiter()

    def describe_instances(self, InstanceIds: list[str]) -> dict[str, Any]:
        """Return the launched instance with the requested key attached."""
        assert InstanceIds == ["i-fresh"]
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-fresh",
                            "InstanceType": "g5.xlarge",
                            "PublicIpAddress": "203.0.113.10",
                            "PrivateIpAddress": "10.0.0.10",
                            "State": {"Name": "running"},
                            "KeyName": "custom-key",
                            "Placement": {"AvailabilityZone": "us-west-2a"},
                        }
                    ]
                }
            ]
        }


class _FakeReuseEc2:
    """Fake EC2 client for the existing-instance reuse path."""

    def describe_instances(self, InstanceIds: list[str]) -> dict[str, Any]:
        """Return an existing running instance with its observed key."""
        assert InstanceIds == ["i-reuse"]
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-reuse",
                            "InstanceType": "g5.xlarge",
                            "PublicIpAddress": "203.0.113.20",
                            "PrivateIpAddress": "10.0.0.20",
                            "VpcId": "vpc-reuse",
                            "SubnetId": "subnet-reuse",
                            "State": {"Name": "running"},
                            "KeyName": "reuse-key",
                            "SecurityGroups": [{"GroupId": "sg-reuse"}],
                            "Placement": {"AvailabilityZone": "us-west-2a"},
                        }
                    ]
                }
            ]
        }


def test_aws_fresh_launch_stdout_emits_specified_key_contract(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Fresh AWS launch should request KeyName and emit described-instance key evidence."""
    module = load_vm_script("launch_instance.py")
    fake_ec2 = _FakeLaunchEc2()

    monkeypatch.setattr(module.boto3, "client", lambda service, region_name: fake_ec2)
    monkeypatch.setattr(module, "get_default_vpc_and_subnets", lambda ec2, instance_type: ("vpc-1", ["subnet-1"]))
    monkeypatch.setattr(module, "create_key_pair", lambda ec2, key_name: f"/tmp/{key_name}.pem")
    monkeypatch.setattr(module, "create_security_group", lambda ec2, vpc_id, sg_name: "sg-1")
    monkeypatch.setattr(module, "get_architecture_for_instance_type", lambda instance_type: "x86_64")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "launch_instance.py",
            "--name",
            "isv-test-gpu",
            "--instance-type",
            "g5.xlarge",
            "--region",
            "us-west-2",
            "--ami-id",
            "ami-test",
            "--key-name",
            "custom-key",
        ],
    )

    exit_code = module.main()

    assert exit_code == 0
    assert fake_ec2.run_instances_calls[0]["KeyName"] == "custom-key"
    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert result["requested_key_name"] == "custom-key"
    assert result["key_name"] == "custom-key"
    assert result["tests"]["specified_key"]["passed"] is True


def test_aws_reuse_stdout_emits_specified_key_contract(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Existing-instance reuse should emit the observed instance key evidence."""
    module = load_vm_script("launch_instance.py")

    monkeypatch.setenv("AWS_VM_INSTANCE_ID", "i-reuse")
    monkeypatch.setenv("AWS_VM_KEY_FILE", "/tmp/reuse-key.pem")
    monkeypatch.setattr(module.boto3, "client", lambda service, region_name: _FakeReuseEc2())

    exit_code = module.reuse_existing_instance("us-west-2", "reuse-key")

    assert exit_code == 0
    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert result["requested_key_name"] == "reuse-key"
    assert result["key_name"] == "reuse-key"
    assert result["tests"]["specified_key"]["passed"] is True


def test_my_isv_vm_demo_launch_emits_specified_key_contract() -> None:
    """my-isv demo launch output should demonstrate the specified-key contract."""
    script = MY_ISV_VM_SCRIPTS / "launch_instance.py"
    env = os.environ | {"ISVCTL_DEMO_MODE": "1"}

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--name",
            "isv-test-gpu",
            "--instance-type",
            "my-isv.gpu.1x",
            "--region",
            "demo-region",
        ],
        capture_output=True,
        env=env,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    result: dict[str, Any] = json.loads(completed.stdout)
    assert result["requested_key_name"] == "isv-test-gpu"
    assert result["key_name"] == "isv-test-gpu"
    assert result["tests"]["specified_key"]["passed"] is True


def test_opennebula_launch_contract_compares_user_and_context_ssh_public_keys() -> None:
    """OpenNebula specified-key evidence compares user and VM-resolved SSH keys."""
    module = load_opennebula_vm_script("launch_instance.py")
    key_blob = b"fake-opennebula-key"
    public_key = f"ssh-ed25519 {base64.b64encode(key_blob).decode()} oneadmin@demo-host"
    expected_fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip("=")

    assert module.normalize_public_key(public_key) == public_key.rsplit(" ", 1)[0]
    assert module.public_key_fingerprint(module.normalize_public_key(public_key)) == expected_fingerprint
    assert module.public_key_fingerprints(public_key) == [expected_fingerprint]

    class _FakeUserApi:
        def info(self, uid: int) -> dict[str, Any]:
            assert uid == 0
            return {"TEMPLATE": {"SSH_PUBLIC_KEY": public_key}}

    fake_one = SimpleNamespace(user=_FakeUserApi())
    assert module.get_user_ssh_public_key(fake_one, SimpleNamespace(UID=0)) == public_key

    result: dict[str, Any] = {"success": True, "platform": "vm", "instance_id": "241"}
    module.add_specified_key_contract(
        result,
        requested_key_names=[expected_fingerprint],
        observed_key_names=[expected_fingerprint],
    )

    assert result["requested_key_name"] == expected_fingerprint
    assert result["key_name"] == expected_fingerprint
    assert result["tests"]["specified_key"]["passed"] is True
    assert result["tests"]["specified_key"]["probes"] == ["user_ssh_public_key", "context_ssh_public_key"]
