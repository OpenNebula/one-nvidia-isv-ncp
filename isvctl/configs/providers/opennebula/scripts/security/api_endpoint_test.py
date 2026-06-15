#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula XML-RPC endpoint isolation."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
from typing import Any
from urllib.parse import urlparse

TEST_NAME = "api_endpoint_isolation"


def _test(passed: bool, message: str) -> dict[str, Any]:
    """Return one provider-neutral subtest result."""
    return {"passed": passed, "message": message} if passed else {"passed": False, "error": message}


def _endpoint_host(xmlrpc_url: str) -> str:
    """Extract the host from an OpenNebula XML-RPC URL."""
    parsed = urlparse(xmlrpc_url)
    host = parsed.hostname
    if not parsed.scheme or not host:
        raise ValueError(f"invalid XML-RPC URL: {xmlrpc_url!r}")
    return host


def _is_non_public_ip(address: str) -> bool:
    """Return True when an IP address is not globally routable."""
    ip = ipaddress.ip_address(address)
    return not ip.is_global


def _resolve_host(host: str) -> tuple[list[str], str | None]:
    """Resolve host to IP addresses, returning a diagnostic error when DNS fails."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return [host], None

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return [], str(e)

    addresses = sorted({info[4][0] for info in infos})
    return addresses, None


def evaluate_endpoint(xmlrpc_url: str) -> dict[str, Any]:
    """Evaluate whether the configured OpenNebula API endpoint is non-public."""
    host = _endpoint_host(xmlrpc_url)
    addresses, resolve_error = _resolve_host(host)
    public_addresses = [address for address in addresses if not _is_non_public_ip(address)]
    private_addresses = [address for address in addresses if _is_non_public_ip(address)]

    dns_non_public = bool(resolve_error) or not public_addresses
    private_only = bool(private_addresses) and not public_addresses

    public_message = (
        f"OpenNebula XML-RPC endpoint {host!r} resolves only to non-public addresses: {private_addresses}"
        if private_only
        else f"OpenNebula XML-RPC endpoint {host!r} has public addresses: {public_addresses}"
    )
    dns_message = (
        f"DNS for {host!r} is non-public"
        if dns_non_public
        else f"DNS for {host!r} resolves to public addresses: {public_addresses}"
    )
    if resolve_error:
        public_message = f"Could not resolve {host!r}: {resolve_error}"
        dns_message = f"{host!r} is not publicly resolvable from this runner: {resolve_error}"

    tests = {
        "probe_api_from_public": _test(private_only or bool(resolve_error), public_message),
        "probe_mgmt_from_public": _test(
            private_only or bool(resolve_error),
            "OpenNebula management API uses the same non-public XML-RPC endpoint",
        ),
        "verify_private_only": _test(private_only, public_message),
        "dns_not_public": _test(dns_non_public, dns_message),
    }

    return {
        "success": all(test["passed"] for test in tests.values()),
        "platform": "security",
        "test_name": TEST_NAME,
        "endpoint": xmlrpc_url,
        "endpoints_tested": 1,
        "resolved_addresses": addresses,
        "tests": tests,
    }


def main() -> int:
    """Run OpenNebula API endpoint isolation checks and emit JSON."""
    parser = argparse.ArgumentParser(description="OpenNebula API endpoint isolation test")
    parser.add_argument("--region", default=os.environ.get("ONE_REGION", "opennebula"))
    parser.add_argument("--xmlrpc-url", default=os.environ.get("ONE_XMLRPC", "http://localhost:2633/RPC2"))
    args = parser.parse_args()

    try:
        result = evaluate_endpoint(args.xmlrpc_url)
        result["region"] = args.region
    except Exception as e:
        result = {
            "success": False,
            "platform": "security",
            "test_name": TEST_NAME,
            "region": args.region,
            "endpoint": args.xmlrpc_url,
            "endpoints_tested": 0,
            "error": str(e),
            "tests": {
                "probe_api_from_public": {"passed": False, "error": str(e)},
                "probe_mgmt_from_public": {"passed": False, "error": str(e)},
                "verify_private_only": {"passed": False, "error": str(e)},
                "dns_not_public": {"passed": False, "error": str(e)},
            },
        }

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
