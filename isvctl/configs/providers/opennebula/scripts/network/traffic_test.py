#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Test OpenNebula VM traffic flow with allowed, blocked, and internet probes."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.network import (  # noqa: E402
    allocate_security_group,
    allow_all_egress_rule,
    build_sg_template,
    cidr_rule_fields,
    create_vnet,
    delete_security_group,
    delete_vnet,
    get_one_server,
    quote,
)
from test_connectivity import (  # noqa: E402
    PING_TARGET_INTERNET,
    _as_list,
    _cleanup_probe_vms,
    _get_field,
    _instantiate_template,
    _nic_id,
    _nic_network_id,
    _parse_ping_latency,
    _vm_nics,
    _wait_for_instance_record,
    _wait_for_vm_running,
    ssh_run,
    wait_for_ssh,
)

DEFAULT_SECURITY_GROUP_ID = "0"
TRAFFIC_TESTS = ("traffic_allowed", "traffic_blocked", "internet_icmp", "internet_http")


def _passed(message: str, **extra: Any) -> dict[str, Any]:
    """Return a passing subtest result."""
    result: dict[str, Any] = {"passed": True, "message": message}
    result.update(extra)
    return result


def _failed(error: str, **extra: Any) -> dict[str, Any]:
    """Return a failing subtest result."""
    result: dict[str, Any] = {"passed": False, "error": error}
    result.update(extra)
    return result


def _icmp_rule(rule_type: str, cidr: str | None = None) -> dict[str, str]:
    """Return an OpenNebula ICMP security-group rule."""
    rule = {
        "PROTOCOL": "ICMP",
        "RULE_TYPE": rule_type.upper(),
    }
    if cidr:
        rule.update(cidr_rule_fields(cidr))
    return rule


def _private_nic_template(vnet_id: str | int, sg_id: str | int) -> str:
    """Return a private NIC template with an explicit security group."""
    return "\n".join(
        [
            "NIC = [",
            f"  NETWORK_ID = {quote(vnet_id)},",
            f"  SECURITY_GROUPS = {quote(sg_id)}",
            "]",
        ]
    )


def _split_sg_ids(value: Any) -> set[str]:
    """Return normalized security group IDs from an OpenNebula value."""
    if value is None:
        return set()
    if isinstance(value, list):
        items = value
    else:
        items = str(value).replace(" ", "").replace("[", "").replace("]", "").replace('"', "").split(",")
    return {str(item).strip() for item in items if str(item).strip()}


def _call_update_vnet(one: Any, network_id: str, template: str, update_type: int) -> None:
    """Update a VNet template, handling pyone naming variants."""
    try:
        one.vn.update(int(network_id), template, update_type)
    except AttributeError:
        one.vn.update_vn(int(network_id), template, update_type)


def _vnet_security_group_ids(one: Any, network_id: str) -> set[str]:
    """Return security groups configured directly on a VNet template."""
    vnet_info = one.vn.info(int(network_id))
    template = _get_field(vnet_info, "TEMPLATE", {})
    template_sgs = _get_field(template, "SECURITY_GROUPS")
    if template_sgs is not None:
        return _split_sg_ids(template_sgs)
    return _split_sg_ids(_get_field(vnet_info, "SECURITY_GROUPS"))


def _clear_default_vnet_security_group(
    one: Any,
    network_id: str,
    timeout: int = 30,
    interval: int = 2,
) -> dict[str, Any]:
    """Remove OpenNebula's default SG from the temporary traffic VNet."""
    before = sorted(_vnet_security_group_ids(one, network_id))
    if DEFAULT_SECURITY_GROUP_ID not in before:
        return _passed("Temporary traffic VNet has no default security group", security_groups=before)

    _call_update_vnet(one, network_id, 'SECURITY_GROUPS = ""', 1)

    deadline = time.time() + timeout
    after = before
    while time.time() < deadline:
        after = sorted(_vnet_security_group_ids(one, network_id))
        if DEFAULT_SECURITY_GROUP_ID not in after:
            return _passed(
                "Default security group removed from temporary traffic VNet",
                before=before,
                after=after,
            )
        time.sleep(interval)

    return _failed(
        "Default security group 0 is still present on temporary traffic VNet",
        before=before,
        after=after,
    )


def _attach_private_nic(one: Any, vm_id: str, vnet_id: str, sg_id: str) -> None:
    """Attach the traffic-test private NIC to a running VM."""
    template = _private_nic_template(vnet_id, sg_id)
    try:
        one.vm.attachnic(int(vm_id), template)
    except AttributeError:
        one.vm.attach_nic(int(vm_id), template)


def _create_traffic_security_groups(
    one: Any,
    suffix: str,
    cidr: str,
    created_sg_ids: list[str],
) -> dict[str, str]:
    """Create the source, allow-target, and deny-target security groups."""
    groups = {
        "source": build_sg_template(
            f"isv-traffic-source-{suffix}",
            "ISV traffic source security group",
            [allow_all_egress_rule(), _icmp_rule("INBOUND", cidr)],
        ),
        "allow": build_sg_template(
            f"isv-traffic-allow-{suffix}",
            "ISV traffic ICMP allow security group",
            [allow_all_egress_rule(), _icmp_rule("INBOUND", cidr)],
        ),
        "deny": build_sg_template(
            f"isv-traffic-deny-{suffix}",
            "ISV traffic ICMP deny security group",
            [allow_all_egress_rule()],
        ),
    }
    security_groups = {}
    for role, template in groups.items():
        sg_id = str(int(allocate_security_group(one, template)))
        created_sg_ids.append(sg_id)
        security_groups[role] = sg_id
    return security_groups


def _launch_traffic_vm(
    *,
    one: Any,
    template_id: int,
    name: str,
    vnet_id: str,
    sg_id: str,
    ssh_nic_id: int,
    vm_wait_timeout: int,
    ip_wait_timeout: int,
    created_vm_ids: list[str],
) -> tuple[str, dict[str, Any]]:
    """Launch one VM, attach the traffic-test NIC, and return its record."""
    vm_id = _instantiate_template(one, template_id, name)
    created_vm_ids.append(vm_id)
    _wait_for_vm_running(one, vm_id, vm_wait_timeout)
    _attach_private_nic(one, vm_id, vnet_id, sg_id)
    _wait_for_vm_running(one, vm_id, vm_wait_timeout)
    record = _wait_for_instance_record(one, vm_id, vnet_id, ssh_nic_id, ip_wait_timeout)
    private_nic_id = _traffic_private_nic_id(one.vm.info(int(vm_id)), vnet_id)
    record["private_nic_id"] = private_nic_id
    record["security_group_id"] = str(sg_id)
    return vm_id, record


def _traffic_private_nic_id(vm_info: Any, vnet_id: str) -> int | None:
    """Return the NIC_ID attached to the temporary traffic VNet."""
    for nic in _vm_nics(vm_info):
        if _nic_network_id(nic) == str(vnet_id):
            return _nic_id(nic)
    return None


def _nic_security_group_ids(nic: Any | None) -> set[str]:
    """Return security groups configured directly on a NIC."""
    if nic is None:
        return set()
    return _split_sg_ids(_get_field(nic, "SECURITY_GROUPS"))


def _security_group_rule_ids(vm_info: Any) -> set[str]:
    """Return security group IDs represented in expanded VM SG rules."""
    template = _get_field(vm_info, "TEMPLATE", {})
    rules = [
        *_as_list(_get_field(template, "SECURITY_GROUP_RULE")),
        *_as_list(_get_field(vm_info, "SECURITY_GROUP_RULE")),
    ]
    return {
        str(rule_id)
        for rule in rules
        if (rule_id := _get_field(rule, "SECURITY_GROUP_ID")) not in (None, "")
    }


def _traffic_private_nic(vm_info: Any, vnet_id: str) -> Any | None:
    """Return the NIC attached to the temporary traffic VNet."""
    for nic in _vm_nics(vm_info):
        if _nic_network_id(nic) == str(vnet_id):
            return nic
    return None


def _verify_traffic_security_groups(
    one: Any,
    records: dict[str, dict[str, Any]],
    network_id: str,
) -> dict[str, Any]:
    """Verify the private traffic NICs use only the per-test security groups."""
    probes = []
    errors = []

    for role, record in records.items():
        vm_id = str(record["instance_id"])
        expected_sg_id = str(record["security_group_id"])
        vm_info = one.vm.info(int(vm_id))
        private_nic = _traffic_private_nic(vm_info, network_id)
        private_nic_id = _nic_id(private_nic) if private_nic is not None else None
        private_sg_ids = _nic_security_group_ids(private_nic)
        rule_sg_ids = _security_group_rule_ids(vm_info)

        probe = {
            "role": role,
            "vm_id": vm_id,
            "private_nic_id": private_nic_id,
            "private_nic_security_groups": sorted(private_sg_ids),
            "expanded_security_group_rule_ids": sorted(rule_sg_ids),
        }
        probes.append(probe)

        if private_nic is None:
            errors.append(f"{role}: traffic NIC on network {network_id} was not found")
            continue
        if private_sg_ids != {expected_sg_id}:
            errors.append(
                f"{role}: private traffic NIC SGs are {sorted(private_sg_ids)}, expected only {expected_sg_id}"
            )

    if errors:
        return _failed("Private traffic NIC security group isolation failed", probes=probes, details="; ".join(errors))
    return _passed("Private traffic NICs have isolated per-test security groups", probes=probes)


def _ping_via_ssh(
    *,
    host: str,
    user: str,
    key_file: str,
    target: str,
    expect_success: bool,
    count: int,
    ping_timeout: int,
    ssh_timeout: int,
) -> dict[str, Any]:
    """Run a ping from the source VM and validate the expected outcome."""
    command = f"ping -c {count} -W {ping_timeout} {shlex.quote(target)}"
    exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=ssh_timeout)
    ping_succeeded = exit_code == 0
    details = (stderr or stdout or f"ping exited with {exit_code}").strip()

    if expect_success and ping_succeeded:
        return _passed(
            "Ping succeeded",
            latency_ms=_parse_ping_latency(stdout),
            target=target,
        )
    if not expect_success and not ping_succeeded:
        return _passed("Ping blocked as expected", target=target)
    if expect_success:
        return _failed("Ping failed but was expected to succeed", target=target, details=details)
    return _failed("Ping succeeded but was expected to be blocked", target=target)


def _http_via_ssh(
    *,
    host: str,
    user: str,
    key_file: str,
    url: str,
    ssh_timeout: int,
) -> dict[str, Any]:
    """Run an HTTPS probe from the source VM."""
    quoted_url = shlex.quote(url)
    command = (
        f"curl -fsS --connect-timeout 5 {quoted_url} >/dev/null "
        f"|| wget -q -T 5 -O /dev/null {quoted_url}"
    )
    exit_code, stdout, stderr = ssh_run(host, user, key_file, command, timeout=ssh_timeout)
    if exit_code == 0:
        return _passed("HTTP probe succeeded", url=url)
    return _failed(
        "HTTP probe failed",
        url=url,
        details=(stderr or stdout or f"command exited with {exit_code}").strip(),
    )


def _base_result(args: argparse.Namespace) -> dict[str, Any]:
    """Build the base traffic-flow result envelope."""
    return {
        "success": False,
        "platform": "network",
        "test_name": "traffic_flow",
        "status": "failed",
        "network_id": "",
        "cidr": args.cidr,
        "template_id": str(args.template_id),
        "instances": [],
        "tests": {name: _failed("not run") for name in TRAFFIC_TESTS},
    }


def _cleanup_resources(
    *,
    one: Any | None,
    vm_ids: list[str],
    sg_ids: list[str],
    network_id: str | None,
    skip_cleanup: bool,
) -> tuple[bool, list[str]]:
    """Clean up temporary OpenNebula resources."""
    if skip_cleanup:
        return False, []

    cleanup_errors = []
    if one is None:
        return True, cleanup_errors

    _cleaned, vm_errors = _cleanup_probe_vms(one, vm_ids, skip_cleanup=False)
    cleanup_errors.extend(vm_errors)

    for sg_id in reversed(sg_ids):
        try:
            delete_security_group(one, sg_id)
        except Exception as e:
            cleanup_errors.append(f"sg:{sg_id}: {e}")

    if network_id:
        try:
            delete_vnet(one, network_id)
        except Exception as e:
            cleanup_errors.append(f"vnet:{network_id}: {e}")

    return True, cleanup_errors


def run_traffic_test(args: argparse.Namespace, one: Any | None = None) -> dict[str, Any]:
    """Run the OpenNebula traffic-flow probes and return the JSON contract result."""
    if not args.key_file:
        raise RuntimeError("--key-file is required for OpenNebula traffic SSH probes")

    one = one or get_one_server(args.xmlrpc_url, args.auth)
    suffix = uuid.uuid4().hex[:8]
    result = _base_result(args)
    network_id: str | None = None
    sg_ids: list[str] = []
    vm_ids: list[str] = []

    try:
        network = create_vnet(
            xmlrpc_url=args.xmlrpc_url,
            auth=args.auth,
            name=f"isv-traffic-vnet-{suffix}",
            cidr=args.cidr,
            subnet_count=1,
            cluster_id=args.cluster_id,
            phydev=args.phydev,
            security_groups=args.security_groups,
            vn_mad=args.vn_mad,
            vxlan_mode=args.vxlan_mode,
            zone=args.region,
            ar_ip=args.ar_ip or None,
            ar_size=args.ar_size,
            guest_mtu=args.guest_mtu or None,
            ip_link_conf=args.ip_link_conf or None,
            filter_ip_spoofing=args.filter_ip_spoofing or None,
            filter_mac_spoofing=args.filter_mac_spoofing or None,
            bridge_type=args.bridge_type or None,
        )
        network_id = str(network["network_id"])
        result["network_id"] = network_id
        result["network_security_groups"] = str(args.security_groups)
        result["tests"]["network_setup"] = _passed("Temporary virtual network created", network_id=network_id)
        result["tests"]["remove_default_vnet_sg"] = _clear_default_vnet_security_group(one, network_id)
        if not result["tests"]["remove_default_vnet_sg"].get("passed"):
            result["tests"]["traffic_blocked"] = _failed(
                "Default security group 0 leaked into temporary traffic VNet policy",
                details=result["tests"]["remove_default_vnet_sg"].get("error", ""),
                before=result["tests"]["remove_default_vnet_sg"].get("before", []),
                after=result["tests"]["remove_default_vnet_sg"].get("after", []),
            )
            raise RuntimeError(result["tests"]["remove_default_vnet_sg"]["error"])

        security_groups = _create_traffic_security_groups(one, suffix, args.cidr, sg_ids)
        result["tests"]["create_security_groups"] = _passed(
            "Traffic security groups created",
            security_groups=security_groups,
        )

        roles = [
            ("source", security_groups["source"]),
            ("target_allow", security_groups["allow"]),
            ("target_deny", security_groups["deny"]),
        ]
        records: dict[str, dict[str, Any]] = {}
        for role, sg_id in roles:
            vm_id, record = _launch_traffic_vm(
                one=one,
                template_id=args.template_id,
                name=f"isv-traffic-{role}-{suffix}",
                vnet_id=network_id,
                sg_id=sg_id,
                ssh_nic_id=args.ssh_nic_id,
                vm_wait_timeout=args.vm_wait_timeout,
                ip_wait_timeout=args.ip_wait_timeout,
                created_vm_ids=vm_ids,
            )
            record["role"] = role
            records[role] = record
            result["instances"].append(record)

        result["tests"]["launch_instances"] = _passed("Traffic probe VMs launched", count=len(records))
        result["tests"]["instances_running"] = _passed("Traffic probe VMs are running", count=len(records))
        result["tests"]["security_group_isolation"] = _verify_traffic_security_groups(one, records, network_id)
        if not result["tests"]["security_group_isolation"].get("passed"):
            result["tests"]["traffic_blocked"] = _failed(
                "Default security group 0 leaked into private traffic NIC policy",
                details=result["tests"]["security_group_isolation"].get("details", ""),
                probes=result["tests"]["security_group_isolation"].get("probes", []),
            )
            raise RuntimeError(result["tests"]["traffic_blocked"]["error"])

        source_public_ip = records["source"].get("public_ip")
        allow_private_ip = records["target_allow"].get("private_ip")
        deny_private_ip = records["target_deny"].get("private_ip")
        if not source_public_ip:
            raise RuntimeError("Source VM has no SSH/public IP")
        if not allow_private_ip:
            raise RuntimeError("Allow target VM has no private IP")
        if not deny_private_ip:
            raise RuntimeError("Deny target VM has no private IP")

        if not wait_for_ssh(source_public_ip, args.ssh_user, args.key_file, args.ssh_wait_timeout):
            raise RuntimeError(f"SSH not ready on source VM at {source_public_ip}")
        result["tests"]["ssm_ready"] = _passed("SSH ready on source VM")

        result["tests"]["traffic_allowed"] = _ping_via_ssh(
            host=source_public_ip,
            user=args.ssh_user,
            key_file=args.key_file,
            target=allow_private_ip,
            expect_success=True,
            count=args.ping_count,
            ping_timeout=args.ping_timeout,
            ssh_timeout=args.ssh_command_timeout,
        )
        result["tests"]["traffic_blocked"] = _ping_via_ssh(
            host=source_public_ip,
            user=args.ssh_user,
            key_file=args.key_file,
            target=deny_private_ip,
            expect_success=False,
            count=args.ping_count,
            ping_timeout=args.ping_timeout,
            ssh_timeout=args.ssh_command_timeout,
        )
        result["tests"]["internet_icmp"] = _ping_via_ssh(
            host=source_public_ip,
            user=args.ssh_user,
            key_file=args.key_file,
            target=PING_TARGET_INTERNET,
            expect_success=True,
            count=args.ping_count,
            ping_timeout=args.ping_timeout,
            ssh_timeout=args.ssh_command_timeout,
        )
        result["tests"]["internet_http"] = _http_via_ssh(
            host=source_public_ip,
            user=args.ssh_user,
            key_file=args.key_file,
            url=args.http_url,
            ssh_timeout=args.ssh_command_timeout,
        )

    except Exception as e:
        result["error"] = str(e)
    finally:
        cleaned_up, cleanup_errors = _cleanup_resources(
            one=one,
            vm_ids=vm_ids,
            sg_ids=sg_ids,
            network_id=network_id,
            skip_cleanup=args.skip_cleanup,
        )
        result["cleanup"] = cleaned_up
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            result["tests"]["cleanup"] = _failed("; ".join(cleanup_errors))

        all_tests_passed = bool(result["tests"]) and all(test.get("passed", False) for test in result["tests"].values())
        result["success"] = all_tests_passed and not cleanup_errors
        result["status"] = "passed" if result["success"] else "failed"

    return result


def main() -> int:
    """Run OpenNebula traffic-flow probes and emit structured JSON."""
    parser = argparse.ArgumentParser(description="Test OpenNebula traffic flow")
    parser.add_argument("--region", required=True, help="Logical region label")
    parser.add_argument("--cidr", default="10.93.0.0/16", help="CIDR for temporary virtual network")
    parser.add_argument("--cluster-id", type=int, default=-1)
    parser.add_argument("--template-id", required=True, type=int, help="OpenNebula VM template ID")
    parser.add_argument("--xmlrpc-url", required=True, help="OpenNebula XML-RPC endpoint")
    parser.add_argument("--auth", required=True, help="OpenNebula auth token")
    parser.add_argument("--phydev", required=True)
    parser.add_argument("--security-groups", default="", help="Optional VNet-level security groups")
    parser.add_argument("--vn-mad", required=True)
    parser.add_argument("--vxlan-mode", required=True)
    parser.add_argument("--ar-ip", default="", help="Optional first IP for the temporary VNet address range")
    parser.add_argument("--ar-size", type=int, default=None, help="Optional size for the temporary VNet address range")
    parser.add_argument("--guest-mtu", default="", help="Optional VNet GUEST_MTU value")
    parser.add_argument("--ip-link-conf", default="", help="Optional VNet IP_LINK_CONF value")
    parser.add_argument("--filter-ip-spoofing", default="", help="Optional VNet FILTER_IP_SPOOFING value")
    parser.add_argument("--filter-mac-spoofing", default="", help="Optional VNet FILTER_MAC_SPOOFING value")
    parser.add_argument("--bridge-type", default="", help="Optional VNet BRIDGE_TYPE value")
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument("--ssh-nic-id", type=int, default=0, help="Template NIC_ID used for SSH access")
    parser.add_argument("--name-prefix", default="isv-traffic", help=argparse.SUPPRESS)
    parser.add_argument("--vm-wait-timeout", type=int, default=600, help="Seconds to wait for VMs to run")
    parser.add_argument("--ip-wait-timeout", type=int, default=120, help="Seconds to wait for VM IP assignment")
    parser.add_argument("--ssh-wait-timeout", type=int, default=300, help="Seconds to wait for SSH access")
    parser.add_argument("--ssh-command-timeout", type=int, default=30, help="Seconds allowed for each remote probe")
    parser.add_argument("--ping-count", type=int, default=3, help="ICMP echo count")
    parser.add_argument("--ping-timeout", type=int, default=2, help="Seconds to wait for each ping reply")
    parser.add_argument("--http-url", default="https://example.com", help="HTTPS URL for internet HTTP probe")
    parser.add_argument("--skip-cleanup", action="store_true", help="Keep temporary resources for debugging")
    args = parser.parse_args()

    try:
        result = run_traffic_test(args)
    except Exception as e:
        result = {
            "success": False,
            "platform": "network",
            "test_name": "traffic_flow",
            "status": "failed",
            "network_id": "",
            "tests": {name: _failed("not run") for name in TRAFFIC_TESTS},
            "error": str(e),
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
