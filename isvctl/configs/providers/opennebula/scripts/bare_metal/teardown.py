#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Teardown an OpenNebula NICo bare-metal VM."""

import argparse
import base64
import json
import os
import ssl
import sys
import time
from typing import Any
from urllib import error, parse, request

try:
    import pyone
except ImportError:
    pyone = None


def env_value(name: str) -> str:
    """Return a required environment value or raise a clear error."""
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value


class NicoAPI:
    """Small NICo client for resources that are not represented in OpenNebula."""

    def __init__(self, timeout: int) -> None:
        self.carbide_proxy = env_value("ONE_BM_NICO_CARBIDE_PROXY").rstrip("/")
        self.ssa_issuer = env_value("ONE_BM_NICO_SSA_ISSUER")
        self.ngc_org = env_value("ONE_BM_NICO_NGC_ORG")
        self.client_id = env_value("ONE_BM_NICO_ISV_CLIENT_ID")
        self.client_secret = env_value("ONE_BM_NICO_ISV_CLIENT_SECRET")
        self.target_scopes = env_value("ONE_BM_NICO_TARGET_SCOPES")
        self.timeout = timeout
        self._jwt: str | None = None
        self._ssl_context = ssl._create_unverified_context()

    def acquire_jwt(self) -> str:
        token_url = parse.urljoin(self.ssa_issuer.rstrip("/") + "/", "/token")
        credentials = f"{self.client_id}:{self.client_secret}".encode()
        body = parse.urlencode({"scope": self.target_scopes, "grant_type": "client_credentials"}).encode()
        req = request.Request(
            token_url,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {base64.b64encode(credentials).decode()}",
            },
            method="POST",
        )
        response = self._open(req)
        token = response.get("access_token")
        if not token:
            raise RuntimeError("JWT response did not include access_token")
        self._jwt = str(token)
        return self._jwt

    def get_allocation(self, allocation_id: str) -> dict[str, Any]:
        jwt = self._jwt or self.acquire_jwt()
        req = request.Request(
            f"{self.carbide_proxy}/v2/org/{self.ngc_org}/forge/allocation/{allocation_id}",
            headers={"Authorization": f"Bearer {jwt}", "Accept": "application/json"},
            method="GET",
        )
        return self._open(req)

    def list_infiniband_partitions(self, site_id: str) -> list[dict[str, Any]]:
        jwt = self._jwt or self.acquire_jwt()
        query = parse.urlencode({"siteId": site_id})
        req = request.Request(
            f"{self.carbide_proxy}/v2/org/{self.ngc_org}/forge/infiniband-partition?{query}",
            headers={"Authorization": f"Bearer {jwt}", "Accept": "application/json"},
            method="GET",
        )
        response = self._open(req)
        if isinstance(response, list):
            return response
        partitions = response.get("items") or response.get("data") or response.get("results") or []
        return [item for item in partitions if isinstance(item, dict)]

    def delete_infiniband_partition(self, partition_id: str) -> None:
        jwt = self._jwt or self.acquire_jwt()
        req = request.Request(
            f"{self.carbide_proxy}/v2/org/{self.ngc_org}/forge/infiniband-partition/{partition_id}",
            headers={"Authorization": f"Bearer {jwt}", "Accept": "application/json"},
            method="DELETE",
        )
        self._open(req)

    def _open(self, req: request.Request) -> dict[str, Any]:
        try:
            with request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                payload = resp.read().decode()
                return json.loads(payload) if payload else {}
        except error.HTTPError as e:
            raise RuntimeError(f"NICo API HTTP {e.code}: {e.read().decode()}") from e
        except error.URLError as e:
            raise RuntimeError(f"NICo API request failed: {e.reason}") from e


def delete_infiniband_partition(name: str, timeout: int) -> str:
    """Delete the named InfiniBand partition in the allocation site if present."""
    allocation_id = env_value("ONE_BM_NICO_ALLOCATION")
    api = NicoAPI(timeout)
    allocation = api.get_allocation(allocation_id)
    site_id = str(allocation.get("siteId") or "")
    if not site_id:
        raise RuntimeError(f"NICo allocation {allocation_id} did not include siteId")

    for partition in api.list_infiniband_partitions(site_id):
        if str(partition.get("name") or "") != name:
            continue
        partition_id = str(partition.get("id") or partition.get("infiniBandPartitionId") or "")
        if not partition_id:
            raise RuntimeError(f"NICo InfiniBand partition {name} did not include id")
        api.delete_infiniband_partition(partition_id)
        return "deleted"

    return "not_found"


def wait_for_vm_terminated(one: object, instance_id: int, timeout: int = 600) -> bool:
    """Wait for a VM to reach DONE or disappear from the pool."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            vm_info = one.vm.info(instance_id)
            if int(getattr(vm_info, "STATE", -1)) == 6:
                return True
        except Exception as e:
            message = str(e).lower()
            if "does not exist" in message or "not found" in message:
                return True

        time.sleep(5)

    return False


def using_existing_instance() -> bool:
    """Return whether the run targets a user-provided existing VM."""
    return bool(os.environ.get("ONE_BM_EXISTING_INSTANCE_ID", "").strip())


def main() -> int:
    """Terminate the OpenNebula VM backing a NICo bare-metal instance."""
    parser = argparse.ArgumentParser(description="Teardown OpenNebula bare-metal instance")
    parser.add_argument("--instance-id", type=int, required=True, help="OpenNebula VM ID")
    parser.add_argument("--template-id", type=int, help="OpenNebula VM template ID to delete")
    parser.add_argument("--host-id", type=int, help="OpenNebula host ID to delete")
    parser.add_argument("--infiniband-partition-name", help="NICo InfiniBand partition name to delete")
    parser.add_argument("--nico-api-timeout", type=int, default=60, help="Seconds for NICo API requests")
    parser.add_argument("--skip-destroy", action="store_true", help="Skip VM termination")
    args = parser.parse_args()

    result: dict[str, object] = {
        "success": False,
        "platform": "bm",
        "instance_id": str(args.instance_id),
        "template_id": str(args.template_id) if args.template_id is not None else None,
        "host_id": str(args.host_id) if args.host_id is not None else None,
        "infiniband_partition_name": args.infiniband_partition_name,
        "cleanup": {},
    }

    if args.skip_destroy:
        result["success"] = True
        result["skipped"] = True
        result["state"] = "running"
        print(json.dumps(result, indent=2))
        return 0

    if using_existing_instance():
        result["success"] = True
        result["skipped"] = True
        result["state"] = "running"
        result["message"] = "Skipping teardown for ONE_BM_EXISTING_INSTANCE_ID"
        result["cleanup"] = {
            "instance": "skipped_existing_instance",
            "template": "skipped_existing_instance",
            "host": "skipped_existing_instance",
        }
        print(json.dumps(result, indent=2))
        return 0

    if pyone is None:
        print("Error: pyone is not installed. Please install pyone.", file=sys.stderr)
        return 1

    xmlrpc_url = os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2")
    auth = os.environ.get("ONE_AUTH", "oneadmin:opennebula")

    try:
        one = pyone.OneServer(xmlrpc_url, session=auth)
        one.vm.action("terminate-hard", args.instance_id)
        wait_for_vm_terminated(one, args.instance_id)

        result["state"] = "terminated"

        cleanup = result["cleanup"]
        if args.template_id is not None:
            try:
                one.template.delete(args.template_id)
                cleanup["template"] = "deleted"
            except Exception as e:
                cleanup["template"] = f"failed: {e}"

        if args.host_id is not None:
            try:
                one.host.delete(args.host_id)
                cleanup["host"] = "deleted"
            except Exception as e:
                cleanup["host"] = f"failed: {e}"

        if args.infiniband_partition_name:
            try:
                cleanup["infiniband_partition"] = delete_infiniband_partition(
                    args.infiniband_partition_name,
                    args.nico_api_timeout,
                )
            except Exception as e:
                cleanup["infiniband_partition"] = f"failed: {e}"

        result["success"] = True
    except Exception as e:
        message = str(e)
        if "does not exist" in message or "not found" in message.lower():
            result["state"] = "terminated"
            result["success"] = True
            result["already_deleted"] = True
        else:
            result["error"] = message

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
