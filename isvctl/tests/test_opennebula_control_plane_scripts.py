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

"""Tests for OpenNebula control-plane scripts."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ISVCTL_ROOT = Path(__file__).resolve().parents[1]
OPENNEBULA_CONTROL_PLANE_SCRIPTS = (
    ISVCTL_ROOT / "configs" / "providers" / "opennebula" / "scripts" / "control-plane"
)


def _load_control_plane_script(script_name: str) -> ModuleType:
    """Load an OpenNebula control-plane script as a module."""
    script_path = OPENNEBULA_CONTROL_PLANE_SCRIPTS / script_name
    spec = importlib.util.spec_from_file_location(f"test_opennebula_{script_path.stem}", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeOpenNebula:
    """Small fake OpenNebula client covering control-plane lifecycle calls."""

    def __init__(self) -> None:
        """Initialize fake users and groups."""
        self.users: dict[int, dict[str, str]] = {}
        self.groups: dict[int, dict[str, str]] = {}
        self.next_user_id = 100
        self.next_group_id = 200
        self.deleted_users: list[int] = []
        self.deleted_groups: list[int] = []
        self.user = SimpleNamespace(
            allocate=self.allocate_user,
            passwd=self.change_password,
            delete=self.delete_user,
        )
        self.userpool = SimpleNamespace(info=self.userpool_info)
        self.group = SimpleNamespace(
            allocate=self.allocate_group,
            delete=self.delete_group,
        )
        self.grouppool = SimpleNamespace(info=self.grouppool_info)
        self.system = SimpleNamespace(version=lambda: "6.10.0")

    def allocate_user(self, username: str, password: str, auth_driver: str = "core") -> int:
        """Allocate a fake user."""
        user_id = self.next_user_id
        self.next_user_id += 1
        self.users[user_id] = {"ID": str(user_id), "NAME": username, "PASSWORD": password, "AUTH": auth_driver}
        return user_id

    def change_password(self, user_id: int, password: str, *_args: Any) -> None:
        """Change a fake user's password."""
        self.users[user_id]["PASSWORD"] = password

    def delete_user(self, user_id: int) -> None:
        """Delete a fake user."""
        self.deleted_users.append(user_id)
        self.users.pop(user_id, None)

    def userpool_info(self, *_args: Any) -> SimpleNamespace:
        """Return fake user pool entries."""
        return SimpleNamespace(USER=[SimpleNamespace(**user) for user in self.users.values()])

    def allocate_group(self, group_name: str) -> int:
        """Allocate a fake group."""
        group_id = self.next_group_id
        self.next_group_id += 1
        self.groups[group_id] = {"ID": str(group_id), "NAME": group_name}
        return group_id

    def delete_group(self, group_id: int) -> None:
        """Delete a fake group."""
        self.deleted_groups.append(group_id)
        self.groups.pop(group_id, None)

    def grouppool_info(self, *_args: Any) -> SimpleNamespace:
        """Return fake group pool entries."""
        return SimpleNamespace(GROUP=[SimpleNamespace(**group) for group in self.groups.values()])


def _payload(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    """Return JSON emitted by a script main call."""
    return json.loads(capsys.readouterr().out)


def test_opennebula_create_access_key_contract(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Access-key setup emits the fields consumed by AccessKeyCreatedCheck."""
    module = _load_control_plane_script("create_access_key.py")
    fake = FakeOpenNebula()
    monkeypatch.setattr(module, "get_one_server", lambda *_args: fake)
    monkeypatch.setattr(sys, "argv", ["create_access_key.py", "--region", "one", "--xmlrpc-url", "url", "--auth", "a:b"])

    exit_code = module.main()
    payload = _payload(capsys)

    assert exit_code == 0
    assert payload["success"] is True
    assert payload["username"].startswith("isv-access-key-test-")
    assert payload["access_key_id"] == payload["username"]
    assert payload["secret_access_key"]
    assert payload["user_id"] == "100"


def test_opennebula_access_key_auth_and_rejection_contracts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Authentication and rejection scripts emit the expected lifecycle fields."""
    auth_module = _load_control_plane_script("test_access_key.py")
    reject_module = _load_control_plane_script("verify_key_rejected.py")

    def fake_server(_url: str, session: str) -> FakeOpenNebula:
        if session == "user:old-password":
            return FakeOpenNebula()
        raise RuntimeError("Authentication failed")

    monkeypatch.setattr(auth_module, "get_one_server", fake_server)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_access_key.py",
            "--access-key-id",
            "user",
            "--secret-access-key",
            "old-password",
            "--region",
            "one",
            "--xmlrpc-url",
            "url",
            "--retries",
            "1",
        ],
    )
    assert auth_module.main() == 0
    auth_payload = _payload(capsys)
    assert auth_payload["authenticated"] is True
    assert auth_payload["identity_id"] == "user"

    monkeypatch.setattr(reject_module, "get_one_server", lambda *_args: (_ for _ in ()).throw(RuntimeError("denied")))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_key_rejected.py",
            "--access-key-id",
            "user",
            "--secret-access-key",
            "old-password",
            "--region",
            "one",
            "--xmlrpc-url",
            "url",
            "--retries",
            "1",
        ],
    )
    assert reject_module.main() == 0
    reject_payload = _payload(capsys)
    assert reject_payload["success"] is True
    assert reject_payload["rejected"] is True
    assert reject_payload["error_code"] == "AuthenticationError"


def test_opennebula_disable_and_delete_access_key_contracts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Disable and teardown scripts find the user and emit validation fields."""
    fake = FakeOpenNebula()
    user_id = fake.allocate_user("test-user", "old-password")

    disable_module = _load_control_plane_script("disable_access_key.py")
    monkeypatch.setattr(disable_module, "get_one_server", lambda *_args: fake)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "disable_access_key.py",
            "--username",
            "test-user",
            "--access-key-id",
            "test-user",
            "--xmlrpc-url",
            "url",
            "--auth",
            "a:b",
        ],
    )
    assert disable_module.main() == 0
    disable_payload = _payload(capsys)
    assert disable_payload["status"] == "Inactive"
    assert fake.users[user_id]["PASSWORD"] != "old-password"

    delete_module = _load_control_plane_script("delete_access_key.py")
    monkeypatch.setattr(delete_module, "get_one_server", lambda *_args: fake)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "delete_access_key.py",
            "--username",
            "test-user",
            "--access-key-id",
            "test-user",
            "--region",
            "one",
            "--xmlrpc-url",
            "url",
            "--auth",
            "a:b",
        ],
    )
    assert delete_module.main() == 0
    delete_payload = _payload(capsys)
    assert delete_payload["success"] is True
    assert delete_payload["deleted_user"] == "test-user"
    assert fake.deleted_users == [user_id]


def test_opennebula_tenant_lifecycle_contracts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Tenant scripts emit the fields consumed by tenant lifecycle checks."""
    fake = FakeOpenNebula()
    tenant_id = fake.allocate_group("tenant-a")

    list_module = _load_control_plane_script("list_tenants.py")
    monkeypatch.setattr(list_module, "get_one_server", lambda *_args: fake)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "list_tenants.py",
            "--region",
            "one",
            "--xmlrpc-url",
            "url",
            "--auth",
            "a:b",
            "--group-name",
            "tenant-a",
        ],
    )
    assert list_module.main() == 0
    list_payload = _payload(capsys)
    assert list_payload["found_target"] is True
    assert list_payload["target_tenant"] == "tenant-a"
    assert list_payload["count"] == 1

    get_module = _load_control_plane_script("get_tenant.py")
    monkeypatch.setattr(get_module, "get_one_server", lambda *_args: fake)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "get_tenant.py",
            "--group-name",
            "tenant-a",
            "--region",
            "one",
            "--xmlrpc-url",
            "url",
            "--auth",
            "a:b",
        ],
    )
    assert get_module.main() == 0
    get_payload = _payload(capsys)
    assert get_payload["tenant_name"] == "tenant-a"
    assert get_payload["tenant_id"] == str(tenant_id)

    delete_module = _load_control_plane_script("delete_tenant.py")
    monkeypatch.setattr(delete_module, "get_one_server", lambda *_args: fake)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "delete_tenant.py",
            "--group-name",
            "tenant-a",
            "--region",
            "one",
            "--xmlrpc-url",
            "url",
            "--auth",
            "a:b",
        ],
    )
    assert delete_module.main() == 0
    delete_payload = _payload(capsys)
    assert delete_payload["success"] is True
    assert delete_payload["deleted_group"] == "tenant-a"
    assert fake.deleted_groups == [tenant_id]
