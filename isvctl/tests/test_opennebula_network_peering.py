# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Tests for OpenNebula network peering helpers."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ISVCTL_ROOT = Path(__file__).resolve().parents[1]
OPENNEBULA_NETWORK_SCRIPTS = ISVCTL_ROOT / "configs" / "providers" / "opennebula" / "scripts" / "network"


def load_opennebula_network_script(script_name: str) -> ModuleType:
    """Load an OpenNebula network script as a module."""
    script_path = OPENNEBULA_NETWORK_SCRIPTS / script_name
    spec = importlib.util.spec_from_file_location(f"test_opennebula_network_{script_path.stem}", script_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {script_path}")

    sys.path.insert(0, str(script_path.parent))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_peering_vrouter_template_links_both_networks() -> None:
    """The Virtual Router template includes both network NICs and gateway IPs."""
    module = load_opennebula_network_script("peering_test.py")

    template = module._vrouter_template("peer-vr", "101", "172.20.1.1", "102", "172.20.2.1")

    assert 'NAME = "peer-vr"' in template
    assert 'NETWORK_ID = "101"' in template
    assert 'NETWORK_ID = "102"' in template
    assert 'IP = "172.20.1.1"' in template
    assert 'IP = "172.20.2.1"' in template


def test_peering_base_result_matches_validation_contract() -> None:
    """The base result contains every VpcPeeringCheck-required subtest."""
    module = load_opennebula_network_script("peering_test.py")
    args = argparse.Namespace(cidr_a="172.20.1.0/24", cidr_b="172.20.2.0/24", gateway_a="", gateway_b="")

    result = module._base_result(args)

    assert result["platform"] == "network"
    assert result["vpc_a"] == {"id": "", "cidr": "172.20.1.0/24", "gateway": "172.20.1.1"}
    assert result["vpc_b"] == {"id": "", "cidr": "172.20.2.0/24", "gateway": "172.20.2.1"}
    assert set(result["tests"]) == set(module.PEERING_TESTS)


def test_peering_route_command_targets_peer_cidr_via_vrouter_gateway() -> None:
    """The route setup command uses a peer-specific route through the VRouter gateway."""
    module = load_opennebula_network_script("peering_test.py")

    command = module._route_command("172.20.1.2", "172.20.2.0/24", "172.20.1.1", "172.20.2.2")

    assert "private_ip=172.20.1.2" in command
    assert "peer_cidr=172.20.2.0/24" in command
    assert "gateway=172.20.1.1" in command
    assert 'route replace "$peer_cidr" via "$gateway" dev "$iface"' in command


class _FakeVRouterInfo:
    """Minimal pyone-like Virtual Router info object."""

    def __init__(self) -> None:
        """Initialize the fake info object."""
        self.TEMPLATE = {"NIC": [{"NETWORK_ID": "101"}, {"NETWORK_ID": "102"}]}
        self.VMS = {"ID": [201, 202]}


def test_peering_vrouter_info_extractors_accept_pyone_shapes() -> None:
    """VRouter helpers read network and VM IDs from pyone-like objects."""
    module = load_opennebula_network_script("peering_test.py")
    info = _FakeVRouterInfo()

    assert module._vrouter_network_ids(info) == {"101", "102"}
    assert module._vrouter_vm_ids(info) == ["201", "202"]


class _FakeVmPool:
    """Minimal VM endpoint for cleanup-order checks."""

    def __init__(self, calls: list[str]) -> None:
        """Initialize the fake VM endpoint."""
        self.calls = calls

    def info(self, vm_id: int) -> dict[str, int]:
        """Return a DONE VM and record the lookup."""
        self.calls.append(f"vm.info:{vm_id}")
        return {"STATE": 6, "LCM_STATE": 0}

    def action(self, action: str, vm_id: int) -> None:
        """Record VM actions."""
        self.calls.append(f"vm.action:{action}:{vm_id}")


class _FakeVRouterPool:
    """Minimal VRouter endpoint for cleanup-order checks."""

    def __init__(self, calls: list[str]) -> None:
        """Initialize the fake VRouter endpoint."""
        self.calls = calls
        self.deleted = False

    def delete(self, vrouter_id: int, *_args: object) -> None:
        """Record VRouter deletion."""
        self.calls.append(f"vrouter.delete:{vrouter_id}")
        self.deleted = True

    def info(self, vrouter_id: int) -> dict[str, int]:
        """Raise once the fake VRouter is deleted."""
        self.calls.append(f"vrouter.info:{vrouter_id}")
        if self.deleted:
            raise RuntimeError("deleted")
        return {"ID": vrouter_id}


class _FakeVnPool:
    """Minimal VNet endpoint for cleanup-order checks."""

    def __init__(self, calls: list[str]) -> None:
        """Initialize the fake VNet endpoint."""
        self.calls = calls

    def delete(self, network_id: int) -> None:
        """Record VNet deletion."""
        self.calls.append(f"vn.delete:{network_id}")


class _FakeOne:
    """Minimal OpenNebula client for cleanup-order checks."""

    def __init__(self) -> None:
        """Initialize fake OpenNebula endpoints."""
        self.calls: list[str] = []
        self.vm = _FakeVmPool(self.calls)
        self.vrouter = _FakeVRouterPool(self.calls)
        self.vn = _FakeVnPool(self.calls)


def test_cleanup_waits_for_vrouter_vm_before_vnet_delete() -> None:
    """Cleanup waits for probe and VRouter VMs before deleting VNets."""
    module = load_opennebula_network_script("peering_test.py")
    fake_one = _FakeOne()

    cleaned_up, cleanup_errors = module._cleanup_resources(
        one=fake_one,
        vm_ids=["778", "779"],
        vrouter_vm_ids=["777"],
        vrouter_id="78",
        network_ids=["339", "340"],
        skip_cleanup=False,
    )

    assert cleaned_up is True
    assert cleanup_errors == []
    first_vnet_delete = fake_one.calls.index("vn.delete:340")
    assert fake_one.calls.index("vm.info:777") < first_vnet_delete
    assert fake_one.calls.index("vm.info:778") < first_vnet_delete
    assert fake_one.calls.index("vm.info:779") < first_vnet_delete


def test_common_vnet_template_can_declare_gateway() -> None:
    """The shared VNet helper renders GATEWAY when requested."""
    scripts_root = ISVCTL_ROOT / "configs" / "providers" / "opennebula" / "scripts"
    sys.path.insert(0, str(scripts_root))
    from common.network import build_vnet_template

    template = build_vnet_template(
        name="peer-a",
        cidr="172.20.1.0/24",
        subnet_count=1,
        phydev="eth0",
        security_groups="0",
        vn_mad="vxlan",
        vxlan_mode="evpn",
        description="test",
        gateway="172.20.1.1",
    )

    assert 'GATEWAY = "172.20.1.1"' in template
