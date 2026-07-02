#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Create or update the OpenNebula VM template used by the NICo driver."""

import argparse
import json
import os
import sys
import uuid
from typing import Any

try:
    import pyone
except ImportError:
    print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
    sys.exit(1)


def get_value(item: Any, key: str, default: Any = None) -> Any:
    """Return a value from a dict-like or attribute-based pyone object."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def quote(value: str) -> str:
    """Quote a scalar value for an OpenNebula template."""
    return json.dumps(str(value))


def env_value(name: str) -> str:
    """Return a required environment value or raise a clear error."""
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value


BASE_USER_DATA = r"""#cloud-config
autoinstall:
    version: 1
    identity:
        hostname: demo-host
        password: $6$jCfWFbdxh1lK09sY$pxFnrW/yXewYFmgoaywu3WKhdPQg0e8DR8jvedAV.udXM0.i5M6wr4Up2S7ZCN9kNDmg.s7fmrOaXE6nEyzPb/ # Welcome123
        username: ubuntu
    ntp:
        enabled: true
        ntp_client: chrony
        servers:
            - 129.6.15.32
    keyboard:
        layout: us
        toggle: null
        variant: ""
    locale: en_US
    ssh:
        allow-pw: true
        authorized-keys: []
        install-server: true
    user-data:
        users:
            - default
            - name: admin
              gecos: Admin
              sudo: ALL=(ALL) NOPASSWD:ALL
              groups: sudo
              lock_passwd: false
              ssh_authorized_keys: []
        write_files:
            - path: /etc/sudoers.d/nopasswd-sudo-group
              content: |
                %sudo ALL=(ALL) NOPASSWD:ALL
              permissions: '0440'
              owner: root:root
        runcmd:
            - sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 99999/' /etc/ssh/sshd_config
            - 'passwd -u ubuntu || true'
            - 'passwd -u admin || true'
"""

def build_user_data(extra_public_key: str = "") -> str:
    """Return base cloud-config, appending the caller public key if present."""
    if not extra_public_key:
        return BASE_USER_DATA

    ssh_marker = "        authorized-keys: []"
    admin_marker = "              ssh_authorized_keys: []"

    return BASE_USER_DATA.replace(
        ssh_marker,
        f"        authorized-keys:\n            - {extra_public_key}",
        1,
    ).replace(
        admin_marker,
        f"              ssh_authorized_keys:\n                - {extra_public_key}",
        1,
    )


def build_template(args: argparse.Namespace) -> str:
    """Build the NICo VM template body described by the driver documentation."""
    lines = [
        f"NAME = {quote(args.name)}",
        "CPU = 1",
        "MEMORY = 1",
        f"NICO_INSTANCE_TYPE_ID = {quote(args.instance_type_id)}",
        f"NICO_OS_ID = {quote(args.os_id)}",
        f"NICO_SSH_KEY_GROUP_IDS = {quote(args.ssh_key_group_ids)}",
        f"NICO_USER_DATA = {quote(args.user_data)}",
        f"NICO_VPC_ID = {quote(args.vpc_id)}",
        "NIC = [",
        f"  NICO_VPC_PREFIX_ID = {quote(args.vpc_prefix_id)}",
        "]",
        "NIC_IB = [",
        f"  PARTITION_NAME = {quote(args.infiniband_partition_name)}",
        "]",
        f"SCHED_REQUIREMENTS = {quote(args.sched_requirements)}",
    ]

    return "\n".join(lines)


def object_dict(value: Any) -> dict[str, Any]:
    """Return a plain dict from a dict-like or pyone object."""
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    return {}


def main() -> int:
    """Create or update a NICo VM template and emit its ID."""
    parser = argparse.ArgumentParser(description="Prepare OpenNebula NICo VM template")
    parser.add_argument("--name", default="isv-bm-nico-template", help="VM template name prefix")
    args = parser.parse_args()
    existing_template_id = os.environ.get("ONE_BM_EXISTING_TEMPLATE_ID", "")
    args.name = f"{args.name}-{uuid.uuid4().hex[:8]}"
    args.ssh_pubkey = os.environ.get("ONE_BM_NICO_SSH_PUBKEY", "")

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    result: dict[str, Any] = {
        "success": False,
        "platform": "bm",
        "template_name": args.name,
    }

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        if existing_template_id:
            template_id = int(existing_template_id)
            template = one.template.info(template_id)
            template_body = object_dict(get_value(template, "TEMPLATE", {}))
            nics = get_value(template_body, "NIC", [])
            if not isinstance(nics, list):
                nics = [nics]
            first_nic = object_dict(nics[0]) if nics else {}
            nic_ibs = get_value(template_body, "NIC_IB", [])
            if not isinstance(nic_ibs, list):
                nic_ibs = [nic_ibs]
            first_nic_ib = object_dict(nic_ibs[0]) if nic_ibs else {}
            result["template_id"] = str(template_id)
            result["template_name"] = str(get_value(template, "NAME", "")) or f"template-{template_id}"
            result["instance_type_id"] = str(template_body.get("NICO_INSTANCE_TYPE_ID") or "")
            result["vpc_id"] = str(template_body.get("NICO_VPC_ID") or "")
            result["vpc_prefix_id"] = str(first_nic.get("NICO_VPC_PREFIX_ID") or "")
            result["infiniband_partition_name"] = str(first_nic_ib.get("PARTITION_NAME") or "")
            result["user_data_public_key"] = bool(template_body.get("NICO_USER_DATA"))
            result["user_data_extra_public_key"] = bool(args.ssh_pubkey)
            result["existing_template"] = True
            result["success"] = True
            print(json.dumps(result, indent=2))
            return 0

        args.instance_type_id = env_value("ONE_BM_NICO_INSTANCE_TYPE_ID")
        args.os_id = env_value("ONE_BM_NICO_OS_ID")
        args.ssh_key_group_ids = env_value("ONE_BM_NICO_SSH_KEY_GROUP_IDS")
        args.user_data = build_user_data(args.ssh_pubkey)
        args.vpc_id = env_value("ONE_BM_NICO_VPC_ID")
        args.vpc_prefix_id = env_value("ONE_BM_NICO_VPC_PREFIX_ID")
        args.infiniband_partition_name = f"ib-test-{uuid.uuid4().hex[:8]}"
        args.sched_requirements = env_value("ONE_BM_NICO_SCHED_REQUIREMENTS")

        template_body = build_template(args)
        template_id = int(one.template.allocate(template_body))

        result["template_id"] = str(template_id)
        result["instance_type_id"] = args.instance_type_id
        result["vpc_id"] = args.vpc_id
        result["vpc_prefix_id"] = args.vpc_prefix_id
        result["infiniband_partition_name"] = args.infiniband_partition_name
        result["user_data_public_key"] = True
        result["user_data_extra_public_key"] = bool(args.ssh_pubkey)
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
