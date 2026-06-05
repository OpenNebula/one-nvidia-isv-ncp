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

"""Tests for OpenNebula security scripts."""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ISVCTL_ROOT = Path(__file__).resolve().parents[1]
OPENNEBULA_SECURITY_SCRIPTS = ISVCTL_ROOT / "configs" / "providers" / "opennebula" / "scripts" / "security"


def _load_security_script(script_name: str) -> ModuleType:
    """Load an OpenNebula security script as a module."""
    script_path = OPENNEBULA_SECURITY_SCRIPTS / script_name
    spec = importlib.util.spec_from_file_location(f"test_opennebula_{script_path.stem}", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _payload(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    """Return JSON emitted by a script main call."""
    return json.loads(capsys.readouterr().out)


def test_opennebula_api_endpoint_isolation_accepts_private_xmlrpc_url(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Private XML-RPC endpoints emit the ApiEndpointIsolationCheck contract."""
    module = _load_security_script("api_endpoint_test.py")

    monkeypatch.setattr(module, "_resolve_host", lambda _host: (["10.0.0.15"], None))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "api_endpoint_test.py",
            "--region",
            "one",
            "--xmlrpc-url",
            "http://one.example.internal:2633/RPC2",
        ],
    )

    exit_code = module.main()
    payload = _payload(capsys)

    assert exit_code == 0
    assert payload["success"] is True
    assert payload["test_name"] == "api_endpoint_isolation"
    assert payload["endpoints_tested"] == 1
    assert set(payload["tests"]) == {
        "probe_api_from_public",
        "probe_mgmt_from_public",
        "verify_private_only",
        "dns_not_public",
    }
    assert all(test["passed"] is True for test in payload["tests"].values())


def test_opennebula_api_endpoint_isolation_rejects_public_xmlrpc_url() -> None:
    """Globally routable XML-RPC endpoints fail the endpoint isolation checks."""
    module = _load_security_script("api_endpoint_test.py")

    payload = module.evaluate_endpoint("https://8.8.8.8:2633/RPC2")

    assert payload["success"] is False
    assert payload["tests"]["verify_private_only"]["passed"] is False
    assert payload["tests"]["dns_not_public"]["passed"] is False


def test_opennebula_api_endpoint_isolation_treats_unresolvable_dns_as_not_private() -> None:
    """Unresolvable DNS is not public DNS evidence but does not prove private-only routing."""
    module = _load_security_script("api_endpoint_test.py")

    def fail_resolve(_host: str) -> tuple[list[str], str]:
        """Return a fake DNS failure."""
        return [], str(socket.gaierror("not found"))

    module._resolve_host = fail_resolve
    payload = module.evaluate_endpoint("http://missing.example.invalid:2633/RPC2")

    assert payload["success"] is False
    assert payload["tests"]["probe_api_from_public"]["passed"] is True
    assert payload["tests"]["verify_private_only"]["passed"] is False
    assert payload["tests"]["dns_not_public"]["passed"] is True


def test_opennebula_audit_logging_main_emits_structured_skip(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """OpenNebula SEC08 reference emits a clean check-specific skip."""
    module = _load_security_script("audit_logging_test.py")

    monkeypatch.setattr(sys, "argv", ["audit_logging_test.py", "--region", "one"])

    exit_code = module.main()
    payload = _payload(capsys)

    assert exit_code == 0
    assert payload["success"] is True
    assert payload["audit_log_entry_skipped"] is True
    assert payload["audit_log_retention_skipped"] is True
    assert payload["audit_log_entry_skip_reason"] == module.SKIP_REASON
    assert payload["audit_log_retention_skip_reason"] == module.SKIP_REASON
    assert set(payload) == {
        "success",
        "platform",
        "test_name",
        "audit_log_entry_skipped",
        "audit_log_entry_skip_reason",
        "audit_log_retention_skipped",
        "audit_log_retention_skip_reason",
        "tests",
    }
    assert all(test["passed"] is True and test["skipped"] is True for test in payload["tests"].values())
