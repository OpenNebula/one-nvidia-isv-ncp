#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Shared OpenNebula virtual network helpers."""

from __future__ import annotations

import ipaddress
import time
from typing import Any


def get_one_server(xmlrpc_url: str, auth: str) -> Any:
    """Return an authenticated OpenNebula XML-RPC client."""
    # Lazy import lets callers return JSON errors when pyone is unavailable.
    try:
        import pyone
    except ImportError as e:
        raise RuntimeError("pyone is not installed. Install pyone to run OpenNebula provider scripts.") from e

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


def cidr_rule_fields(cidr: str) -> dict[str, str]:
    """Return OpenNebula security-group IP/SIZE fields for an IPv4 CIDR."""
    network = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 CIDRs are supported for OpenNebula security group rules")
    if network.prefixlen == 0:
        return {}
    return {
        "IP": str(network.network_address),
        "SIZE": str(network.num_addresses),
    }


def build_sg_template(name: str, description: str, rules: list[dict[str, str]]) -> str:
    """Build an OpenNebula security group template."""
    lines = [
        f"NAME = {quote(name)}",
        f"DESCRIPTION = {quote(description)}",
    ]

    for rule in rules:
        lines.append("RULE = [")
        rule_lines = [f"  {key} = {quote(value)}" for key, value in rule.items()]
        lines.append(",\n".join(rule_lines))
        lines.append("]")

    return "\n".join(lines)


def allow_all_egress_rule() -> dict[str, str]:
    """Return a baseline outbound allow-all security group rule."""
    return {"PROTOCOL": "ALL", "RULE_TYPE": "OUTBOUND"}


def tcp_rule(rule_type: str, port: str | int, cidr: str | None = None) -> dict[str, str]:
    """Return a TCP security group rule."""
    rule = {
        "PROTOCOL": "TCP",
        "RULE_TYPE": rule_type.upper(),
        "RANGE": str(port),
    }
    if cidr:
        rule.update(cidr_rule_fields(cidr))
    return rule


def allocate_security_group(one: Any, template: str) -> str:
    """Allocate an OpenNebula security group."""
    return str(int(one.secgroup.allocate(template)))


def update_security_group(one: Any, sg_id: str | int, template: str) -> None:
    """Replace an OpenNebula security group template."""
    one.secgroup.update(int(sg_id), template, 0)


def delete_security_group(one: Any, sg_id: str | int) -> None:
    """Delete an OpenNebula security group."""
    one.secgroup.delete(int(sg_id))


def security_group_exists(one: Any, sg_id: str | int) -> bool:
    """Return whether a security group exists."""
    try:
        one.secgroup.info(int(sg_id))
    except Exception:
        return False
    return True


def wait_for_security_group_deleted(one: Any, sg_id: str | int, timeout: int = 60, interval: int = 2) -> bool:
    """Wait until a security group no longer exists."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        if not security_group_exists(one, sg_id):
            return True
        time.sleep(interval)

    return False


def get_template_rules(sg_info: Any) -> list[Any]:
    """Return security group rules from pyone info."""
    template = get_value(sg_info, "TEMPLATE", {})
    rules = get_value(template, "RULE", [])
    if rules is None:
        return []
    if isinstance(rules, list):
        return rules
    return [rules]


def rule_matches(
    rule: Any,
    *,
    protocol: str | None = None,
    rule_type: str | None = None,
    port: str | int | None = None,
    cidr: str | None = None,
) -> bool:
    """Return whether an OpenNebula security group rule matches the requested fields."""
    if protocol and str(get_value(rule, "PROTOCOL", "")).upper() != protocol.upper():
        return False
    if rule_type and str(get_value(rule, "RULE_TYPE", "")).upper() != rule_type.upper():
        return False
    if port is not None:
        expected_port = str(port)
        rule_range = str(get_value(rule, "RANGE", ""))
        if rule_range not in (expected_port, f"{expected_port}:{expected_port}"):
            return False
    if cidr:
        fields = cidr_rule_fields(cidr)
        if not fields:
            rule_ip = get_value(rule, "IP")
            rule_size = get_value(rule, "SIZE")
            return rule_ip in (None, "") and rule_size in (None, "")
        if str(get_value(rule, "IP", "")) != fields["IP"]:
            return False
        if str(get_value(rule, "SIZE", "")) != fields["SIZE"]:
            return False
    return True


def has_security_group_rule(
    sg_info: Any,
    *,
    protocol: str | None = None,
    rule_type: str | None = None,
    port: str | int | None = None,
    cidr: str | None = None,
) -> bool:
    """Return whether a security group has a rule matching the requested fields."""
    return any(
        rule_matches(rule, protocol=protocol, rule_type=rule_type, port=port, cidr=cidr)
        for rule in get_template_rules(sg_info)
    )


def get_rules_by_type(sg_info: Any, rule_type: str) -> list[Any]:
    """Return rules with the requested direction."""
    return [
        rule
        for rule in get_template_rules(sg_info)
        if str(get_value(rule, "RULE_TYPE", "")).upper() == rule_type.upper()
    ]


def wait_for_security_group_rule_state(
    one: Any,
    sg_id: str | int,
    *,
    expected_present: bool,
    protocol: str,
    rule_type: str,
    port: str | int | None = None,
    cidr: str | None = None,
    timeout: float = 10.0,
    interval: float = 0.5,
) -> tuple[bool, float]:
    """Poll security group info until a rule reaches the expected visible state."""
    start = time.monotonic()

    while True:
        sg_info = one.secgroup.info(int(sg_id))
        present = has_security_group_rule(
            sg_info,
            protocol=protocol,
            rule_type=rule_type,
            port=port,
            cidr=cidr,
        )
        elapsed = time.monotonic() - start
        if present is expected_present:
            return True, elapsed
        if elapsed >= timeout:
            return False, elapsed
        time.sleep(interval)


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


def subnet_to_ar(
    subnet: ipaddress.IPv4Network,
    *,
    ar_ip: str | None = None,
    ar_size: int | None = None,
) -> dict[str, Any]:
    """Convert a subnet CIDR to an OpenNebula IPv4 address-range template."""
    if ar_ip:
        first_ip = ipaddress.ip_address(ar_ip)
        if first_ip not in subnet:
            raise ValueError(f"Address-range IP {ar_ip} is not inside {subnet}")
    else:
        first_ip = subnet.network_address + 1 if subnet.num_addresses > 2 else subnet.network_address

    usable_hosts = ar_size if ar_size is not None else max(subnet.num_addresses - 2, 1)
    if usable_hosts < 1:
        raise ValueError("Address-range size must be at least 1")

    return {
        "TYPE": "IP4",
        "IP": str(first_ip),
        "SIZE": str(usable_hosts),
    }


def build_subnet_outputs(
    network_id: str | int,
    cidr: str,
    subnet_count: int,
    zone: str,
    *,
    ar_size: int | None = None,
) -> list[dict[str, Any]]:
    """Return provider-neutral subnet records for OpenNebula address ranges."""
    subnets = split_subnets(cidr, subnet_count)
    return [
        {
            "subnet_id": f"{network_id}:ar-{index}",
            "cidr": str(subnet),
            "az": zone,
            "availability_zone": zone,
            "auto_assign_public_ip": False,
            "available_ips": ar_size if ar_size is not None and subnet_count == 1 else max(subnet.num_addresses - 2, 1),
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
    ar_ip: str | None = None,
    ar_size: int | None = None,
    gateway: str | None = None,
    guest_mtu: str | None = None,
    ip_link_conf: str | None = None,
    filter_ip_spoofing: str | None = None,
    filter_mac_spoofing: str | None = None,
    bridge_type: str | None = None,
) -> str:
    """Build an OpenNebula VXLAN virtual-network template."""
    parsed_cidr = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(parsed_cidr, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 CIDRs are supported for OpenNebula virtual networks")

    lines = [
        f"NAME = {quote(name)}",
        f"DESCRIPTION = {quote(description)}",
        f"VN_MAD = {quote(vn_mad)}",
        f"PHYDEV = {quote(phydev)}",
        f"VXLAN_MODE = {quote(vxlan_mode)}",
        'AUTOMATIC_VLAN_ID = "YES"',
    ]
    if bridge_type:
        lines.append(f"BRIDGE_TYPE = {quote(bridge_type)}")
    if gateway:
        lines.append(f"GATEWAY = {quote(gateway)}")
    if security_groups:
        lines.append(f"SECURITY_GROUPS = {quote(security_groups)}")
    if guest_mtu:
        lines.append(f"GUEST_MTU = {quote(guest_mtu)}")
    if ip_link_conf:
        lines.append(f"IP_LINK_CONF = {quote(ip_link_conf)}")
    if filter_ip_spoofing:
        lines.append(f"FILTER_IP_SPOOFING = {quote(filter_ip_spoofing)}")
    if filter_mac_spoofing:
        lines.append(f"FILTER_MAC_SPOOFING = {quote(filter_mac_spoofing)}")

    subnets = split_subnets(cidr, subnet_count)
    if (ar_ip or ar_size is not None) and len(subnets) != 1:
        raise ValueError("Custom address-range IP/size is only supported for single-subnet virtual networks")

    for subnet in subnets:
        ar = subnet_to_ar(subnet, ar_ip=ar_ip, ar_size=ar_size)
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
    xmlrpc_url: str,
    auth: str,
    name: str,
    cidr: str,
    subnet_count: int,
    cluster_id: int,
    phydev: str,
    security_groups: str,
    vn_mad: str,
    vxlan_mode: str,
    zone: str,
    ar_ip: str | None = None,
    ar_size: int | None = None,
    gateway: str | None = None,
    guest_mtu: str | None = None,
    ip_link_conf: str | None = None,
    filter_ip_spoofing: str | None = None,
    filter_mac_spoofing: str | None = None,
    bridge_type: str | None = None,
) -> dict[str, Any]:
    """Create an OpenNebula VXLAN virtual network and return contract fields."""
    one = get_one_server(xmlrpc_url, auth)
    template = build_vnet_template(
        name=name,
        cidr=cidr,
        subnet_count=subnet_count,
        phydev=phydev,
        security_groups=security_groups,
        vn_mad=vn_mad,
        vxlan_mode=vxlan_mode,
        description="Created by isvctl network validation",
        ar_ip=ar_ip,
        ar_size=ar_size,
        gateway=gateway,
        guest_mtu=guest_mtu,
        ip_link_conf=ip_link_conf,
        filter_ip_spoofing=filter_ip_spoofing,
        filter_mac_spoofing=filter_mac_spoofing,
        bridge_type=bridge_type,
    )
    network_id = allocate_vnet(one, template, cluster_id)
    wait_for_vnet(one, network_id)

    return {
        "network_id": str(network_id),
        "cidr": cidr,
        "subnets": build_subnet_outputs(network_id, cidr, subnet_count, zone, ar_size=ar_size),
        "security_group_id": security_groups,
        "vn_mad": vn_mad,
        "phydev": phydev,
        "vxlan_mode": vxlan_mode,
        "zone": zone,
        "gateway": gateway,
    }
