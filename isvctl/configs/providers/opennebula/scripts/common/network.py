#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Shared OpenNebula virtual network helpers."""

from __future__ import annotations

import ipaddress
import os
import time
from typing import Any


DEFAULT_XMLRPC_URL = "http://localhost:2633/RPC2"
DEFAULT_AUTH = "oneadmin:opennebula"
DEFAULT_PHYDEV = "enP6p3s0np0"
DEFAULT_SECURITY_GROUPS = "0"
DEFAULT_VN_MAD = "vxlan"
DEFAULT_VXLAN_MODE = "evpn"


def get_one_server() -> Any:
    """Return an authenticated OpenNebula XML-RPC client."""
    # Lazy import lets callers return JSON errors when pyone is unavailable.
    try:
        import pyone
    except ImportError as e:
        raise RuntimeError("pyone is not installed. Install pyone to run OpenNebula provider scripts.") from e

    xmlrpc_url = os.environ.get("ONE_XMLRPC", DEFAULT_XMLRPC_URL)
    auth = os.environ.get("ONE_AUTH", DEFAULT_AUTH)
    return pyone.OneServer(xmlrpc_url, session=auth)


def allocate_vnet(one: Any, template: str, cluster_id: int = -1) -> int:
    """Allocate a virtual network, handling pyone versions with different signatures."""
    try:
        return int(one.vn.allocate(template, cluster_id))
    except TypeError:
        return int(one.vn.allocate(template))


def delete_vnet(one: Any, network_id: str | int) -> None:
    """Delete an OpenNebula virtual network."""
    one.vn.delete(int(network_id))


def vnet_exists(one: Any, network_id: str | int) -> bool:
    """Return whether a virtual network exists."""
    try:
        one.vn.info(int(network_id))
    except Exception:
        return False
    return True


def wait_for_vnet_deleted(one: Any, network_id: str | int, timeout: int = 60, interval: int = 2) -> bool:
    """Wait until a virtual network no longer exists."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        if not vnet_exists(one, network_id):
            return True
        time.sleep(interval)

    return False


def wait_for_vnet(one: Any, network_id: str | int, timeout: int = 60, interval: int = 2) -> Any:
    """Wait until a virtual network can be described."""
    deadline = time.time() + timeout
    last_error: Exception | None = None

    while time.time() < deadline:
        try:
            return one.vn.info(int(network_id))
        except Exception as e:
            last_error = e
            time.sleep(interval)

    raise RuntimeError(f"Timed out waiting for virtual network {network_id}: {last_error}")


def get_value(item: Any, key: str, default: Any = None) -> Any:
    """Read a dict key or object attribute."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def quote(value: object) -> str:
    """Render an OpenNebula template value."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def split_subnets(cidr: str, subnet_count: int) -> list[ipaddress.IPv4Network]:
    """Split a network CIDR into the requested number of subnets."""
    network = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 CIDRs are supported for OpenNebula network tests")
    if subnet_count < 1:
        raise ValueError("subnet_count must be at least 1")

    new_prefix = network.prefixlen
    while 2 ** (new_prefix - network.prefixlen) < subnet_count:
        new_prefix += 1

    if new_prefix > 30:
        raise ValueError(f"Cannot split {cidr} into {subnet_count} usable IPv4 subnets")

    return list(network.subnets(new_prefix=new_prefix))[:subnet_count]


def subnet_to_ar(subnet: ipaddress.IPv4Network) -> dict[str, Any]:
    """Convert a subnet CIDR to an OpenNebula IPv4 address-range template."""
    usable_hosts = max(subnet.num_addresses - 2, 1)
    first_ip = subnet.network_address + 1 if subnet.num_addresses > 2 else subnet.network_address
    return {
        "TYPE": "IP4",
        "IP": str(first_ip),
        "SIZE": str(usable_hosts),
    }


def build_subnet_outputs(network_id: str | int, cidr: str, subnet_count: int, zone: str) -> list[dict[str, Any]]:
    """Return provider-neutral subnet records for OpenNebula address ranges."""
    subnets = split_subnets(cidr, subnet_count)
    return [
        {
            "subnet_id": f"{network_id}:ar-{index}",
            "cidr": str(subnet),
            "az": zone,
            "availability_zone": zone,
            "auto_assign_public_ip": False,
            "available_ips": max(subnet.num_addresses - 2, 1),
        }
        for index, subnet in enumerate(subnets)
    ]


def build_vnet_template(
    *,
    name: str,
    cidr: str,
    subnet_count: int,
    phydev: str,
    security_groups: str,
    vn_mad: str,
    vxlan_mode: str,
    description: str,
) -> str:
    """Build an OpenNebula VXLAN virtual-network template."""
    lines = [
        f"NAME = {quote(name)}",
        f"DESCRIPTION = {quote(description)}",
        f"VN_MAD = {quote(vn_mad)}",
        f"PHYDEV = {quote(phydev)}",
        f"SECURITY_GROUPS = {quote(security_groups)}",
        f"VXLAN_MODE = {quote(vxlan_mode)}",
        'AUTOMATIC_VLAN_ID = "YES"',
    ]

    for subnet in split_subnets(cidr, subnet_count):
        ar = subnet_to_ar(subnet)
        lines.extend(
            [
                "AR = [",
                f"  TYPE = {quote(ar['TYPE'])},",
                f"  IP = {quote(ar['IP'])},",
                f"  SIZE = {quote(ar['SIZE'])}",
                "]",
            ]
        )

    return "\n".join(lines)


def create_vnet(
    *,
    name: str,
    cidr: str,
    subnet_count: int,
    cluster_id: int,
    phydev: str,
    security_groups: str,
    vn_mad: str,
    vxlan_mode: str,
    zone: str,
) -> dict[str, Any]:
    """Create an OpenNebula VXLAN virtual network and return contract fields."""
    one = get_one_server()
    template = build_vnet_template(
        name=name,
        cidr=cidr,
        subnet_count=subnet_count,
        phydev=phydev,
        security_groups=security_groups,
        vn_mad=vn_mad,
        vxlan_mode=vxlan_mode,
        description="Created by isvctl network validation",
    )
    network_id = allocate_vnet(one, template, cluster_id)
    wait_for_vnet(one, network_id)

    return {
        "network_id": str(network_id),
        "cidr": cidr,
        "subnets": build_subnet_outputs(network_id, cidr, subnet_count, zone),
        "security_group_id": security_groups,
        "vn_mad": vn_mad,
        "phydev": phydev,
        "vxlan_mode": vxlan_mode,
        "zone": zone,
    }
