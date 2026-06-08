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

"""Tests for OpenNebula observability scripts."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ISVCTL_ROOT = Path(__file__).resolve().parents[1]
OPENNEBULA_OBSERVABILITY_SCRIPTS = ISVCTL_ROOT / "configs" / "providers" / "opennebula" / "scripts" / "observability"


def _load_script(script_name: str) -> ModuleType:
    """Load an OpenNebula observability script as a module."""
    script_path = OPENNEBULA_OBSERVABILITY_SCRIPTS / script_name
    spec = importlib.util.spec_from_file_location(f"test_opennebula_{script_path.stem}", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_opennebula_vpc_flow_logs_emits_observability_contract(tmp_path: Path) -> None:
    """OpenNebula flow-log check emits VpcFlowLogsCheck evidence."""
    script = _load_script("log_availability_test.py")
    flow_log = tmp_path / "oned.log"
    flow_log.write_text(
        "Fri Jun  5 10:22:35 2026 [Z0][ReM][D]: Req:3883 UID:1 IP:127.0.0.1 one.vmpool.infoextended invoked\n",
        encoding="utf-8",
    )

    result = script.check_vpc_flow_logs(network_id="one-vnet-1", flow_log_path=flow_log)

    assert result["success"] is True
    assert result["platform"] == "observability"
    assert result["test_name"] == "vpc_flow_logs"
    assert set(result["tests"]) == {
        "flow_log_endpoint_reachable",
        "flow_logs_configured",
        "traffic_type_all",
        "log_destination_accessible",
    }
    probes = result["tests"]["traffic_type_all"]["probes"]
    assert probes["network_id"] == "one-vnet-1"
    assert probes["log_destination"] == str(flow_log)
    assert probes["traffic_type"] == "ALL"


def test_opennebula_host_syslogs_accepts_oned_log_shape(tmp_path: Path) -> None:
    """OpenNebula host syslog check accepts native oned.log timestamp lines."""
    script = _load_script("log_availability_test.py")
    host_log = tmp_path / "oned.log"
    host_log.write_text(
        "Fri Jun  5 10:22:35 2026 [Z0][PLM][I]: Starting Plan Manager timer action...\n",
        encoding="utf-8",
    )

    result = script.check_host_syslogs(host_log_path=host_log, max_age_minutes=10_000_000)

    assert result["success"] is True
    probes = result["tests"]["entries_recent"]["probes"]
    assert probes["hosts_checked"] == 1
    assert probes["log_source"] == str(host_log)
    assert probes["entry_count"] == 1
    assert probes["latest_timestamp"].startswith("2026-06-05T10:22:35")


def test_opennebula_host_syslogs_fails_empty_log(tmp_path: Path) -> None:
    """OpenNebula host syslog check fails when no entries are available."""
    script = _load_script("log_availability_test.py")
    host_log = tmp_path / "empty.log"
    host_log.write_text("", encoding="utf-8")

    result = script.check_host_syslogs(host_log_path=host_log, max_age_minutes=5)

    assert result["success"] is False
    assert result["tests"]["entries_recent"]["passed"] is False


def test_opennebula_bmc_sel_logs_fails_not_implemented() -> None:
    """OpenNebula BMC SEL check fails until a real implementation exists."""
    script = _load_script("log_availability_test.py")

    result = script.check_bmc_sel_logs(region="opennebula")

    assert result["success"] is False
    assert result["test_name"] == "bmc_sel_logs"
    assert result["error"] == "Not implemented - OpenNebula BMC validation is not implemented"
    assert set(result["tests"]) == {
        "sel_log_endpoint_reachable",
        "sel_log_source_present",
        "sel_entries_queryable",
    }
    for subtest in result["tests"].values():
        assert subtest["passed"] is False
        assert "Not implemented" in subtest["error"]
        assert subtest["probes"]["bmc_endpoints_checked"] == 0


def test_opennebula_bmc_gpu_telemetry_fails_not_implemented() -> None:
    """OpenNebula BMC GPU telemetry check fails until a real implementation exists."""
    script = _load_script("log_availability_test.py")

    result = script.check_bmc_gpu_telemetry(region="opennebula")

    assert result["success"] is False
    assert result["test_name"] == "bmc_gpu_telemetry"
    assert result["error"] == "Not implemented - OpenNebula BMC validation is not implemented"
    assert set(result["tests"]) == {
        "telemetry_endpoint_reachable",
        "gpu_metrics_present",
        "host_os_gap_identified",
        "telemetry_samples_recent",
    }
    for subtest in result["tests"].values():
        assert subtest["passed"] is False
        assert "Not implemented" in subtest["error"]
        assert subtest["probes"]["bmc_endpoints_checked"] == 0
