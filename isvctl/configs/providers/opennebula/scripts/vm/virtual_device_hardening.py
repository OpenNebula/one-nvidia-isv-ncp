#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

"""Validate OpenNebula VM virtual-device hardening evidence.

The OpenNebula equivalent for this VM security check is a guest-side SSH probe
against the launched VM. It checks for USB devices/controllers, shared-clipboard
agents, and desktop-style virtual peripherals that should not be present in a
hardened compute VM.

Usage:
    python virtual_device_hardening.py --instance-id 241 \
        --public-ip 172.20.0.10 --key-file /tmp/one_vm_key
"""

import argparse
import json
import subprocess
import sys
from typing import Any

CLIPBOARD_PATTERNS = (
    "spice-vdagent",
    "vdagent",
    "xrdp-chansrv",
    "vncconfig",
    "vmtoolsd",
)
UNNECESSARY_DEVICE_PATTERNS = (
    "floppy",
    "cd-rom",
    "cdrom",
    "qxl",
    "spice",
    "open-vm-tools",
    "vgauth",
    "vmware",
    "virtualbox",
    "vbox",
    "tablet",
    "audio",
)
USB_DEVICE_PATTERNS = ("usb controller", "usb host")
REQUIRED_TESTS = (
    "usb_devices_disabled",
    "clipboard_disabled",
    "unnecessary_virtual_devices_absent",
)

PROBE_SENTINEL = "---ISVCTL-PROBE---"
PROBES: tuple[tuple[str, str], ...] = (
    (
        "usb_count",
        "if [ -d /sys/bus/usb/devices ]; then "
        "find /sys/bus/usb/devices -mindepth 1 -maxdepth 1 -type l -print 2>/dev/null | wc -l; "
        "else echo 0; fi",
    ),
    ("pci_devices", "command -v lspci >/dev/null 2>&1 && lspci || true"),
    ("processes", "ps -eo comm= 2>/dev/null || true"),
    (
        "services",
        "command -v systemctl >/dev/null 2>&1 && "
        "systemctl list-units --type=service --state=running --no-pager --output=json 2>/dev/null || true",
    ),
    (
        "device_paths",
        "find /dev -maxdepth 1 \\( -name fd0 -o -name dvd \\) -print 2>/dev/null || true",
    ),
)

SIGNAL_BINDINGS: tuple[tuple[str, str, str], ...] = (
    ("usb_signals", "usb_devices_disabled", "USB device/controller signals detected"),
    ("clipboard_signals", "clipboard_disabled", "Clipboard-sharing agent signals detected"),
    (
        "unnecessary_device_signals",
        "unnecessary_virtual_devices_absent",
        "Unnecessary virtual device signals detected",
    ),
)


def ssh_run(
    host: str,
    user: str,
    key_file: str,
    command: str,
    timeout: int = 30,
    connect_timeout: int = 10,
) -> tuple[int, str, str]:
    """Run a command over SSH and return exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                f"ConnectTimeout={connect_timeout}",
                "-o",
                "BatchMode=yes",
                "-i",
                key_file,
                f"{user}@{host}",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or ""
    except Exception as e:
        return 1, "", str(e)


def _compact(text: str, max_length: int = 240) -> str:
    """Collapse whitespace and cap length for one-line diagnostics."""
    compact = " ".join(text.split())
    if len(compact) <= max_length:
        return compact
    return f"{compact[: max_length - 3]}..."


def _matching_lines(text: str, patterns: tuple[str, ...]) -> list[str]:
    """Return lines containing any case-insensitive pattern."""
    matches: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if any(pattern in lowered for pattern in patterns):
            matches.append(stripped)
    return matches


def _running_service_unit_names(systemctl_output: str) -> list[str]:
    """Return running service unit names from systemctl ``--output=json`` output."""
    text = systemctl_output.strip()
    if not text:
        return []

    try:
        units = json.loads(text)
    except json.JSONDecodeError as e:
        msg = "systemctl did not return valid JSON"
        raise ValueError(msg) from e

    if not isinstance(units, list):
        msg = "systemctl JSON output must be a list"
        raise ValueError(msg)

    services: list[str] = []
    for unit in units:
        if not isinstance(unit, dict):
            continue
        normalized = {str(key).lower(): value for key, value in unit.items()}
        unit_name = str(normalized.get("unit") or normalized.get("name") or "")
        if not unit_name.endswith(".service"):
            continue
        active = str(normalized.get("active") or "").lower()
        sub = str(normalized.get("sub") or "").lower()
        if active != "active" or sub != "running":
            continue
        services.append(unit_name)
    return services


def _combined_probe_script() -> str:
    """Build one shell script that emits every probe's output between sentinel markers."""
    parts: list[str] = []
    for name, command in PROBES:
        parts.append(f"echo '{PROBE_SENTINEL} {name}'")
        parts.append(f"({command})")
    return "\n".join(parts)


def _split_probe_outputs(combined: str) -> dict[str, str]:
    """Split combined probe output back into a per-probe dict."""
    outputs: dict[str, list[str]] = {name: [] for name, _ in PROBES}
    current: str | None = None
    for line in combined.splitlines():
        if line.startswith(PROBE_SENTINEL):
            current = line[len(PROBE_SENTINEL) :].strip()
            continue
        if current in outputs:
            outputs[current].append(line)
    return {name: "\n".join(lines) for name, lines in outputs.items()}


def _run_combined_probe(host: str, user: str, key_file: str, timeout: int) -> tuple[dict[str, str] | None, str | None]:
    """Run every guest probe in one SSH session. Returns (outputs, error)."""
    exit_code, stdout, stderr = ssh_run(
        host,
        user,
        key_file,
        _combined_probe_script(),
        timeout=timeout,
        connect_timeout=min(timeout, 10),
    )
    if exit_code != 0:
        return None, _compact(stderr or stdout or f"SSH command exited {exit_code}")
    return _split_probe_outputs(stdout), None


def _collect_guest_probe(host: str, user: str, key_file: str, timeout: int) -> dict[str, Any]:
    """Collect guest-side virtual-device hardening evidence."""
    if not host or not key_file:
        return {"status": "skipped", "reason": "missing SSH details"}

    outputs, error = _run_combined_probe(host, user, key_file, timeout)
    if error is not None:
        return {"status": "unavailable", "error": error}
    if outputs is None:
        return {"status": "unavailable", "error": "guest probe returned no output"}

    usb_count_raw = outputs.get("usb_count", "0").strip()
    if not usb_count_raw.isdigit():
        msg = f"Expected integer output, got {usb_count_raw!r}"
        raise ValueError(msg)
    usb_count = int(usb_count_raw)
    pci_devices = outputs.get("pci_devices", "")
    processes = outputs.get("processes", "")
    services = "\n".join(_running_service_unit_names(outputs.get("services", "")))
    device_paths = outputs.get("device_paths", "")

    usb_signals = [f"usb device entries present: {usb_count}"] if usb_count else []
    usb_signals.extend(_matching_lines(pci_devices, USB_DEVICE_PATTERNS))

    clipboard_signals = _matching_lines(f"{processes}\n{services}", CLIPBOARD_PATTERNS)
    unnecessary_signals = _matching_lines(f"{pci_devices}\n{processes}\n{services}", UNNECESSARY_DEVICE_PATTERNS)
    unnecessary_signals.extend(line.strip() for line in device_paths.splitlines() if line.strip())

    return {
        "status": "completed",
        "usb_device_count": usb_count,
        "usb_signals": usb_signals,
        "clipboard_signals": clipboard_signals,
        "unnecessary_device_signals": unnecessary_signals,
    }


def _base_tests() -> dict[str, dict[str, Any]]:
    """Return passing test entries before applying guest probe failures."""
    return {
        "usb_devices_disabled": {
            "passed": True,
            "probes": ["guest_usb_device_probe"],
            "message": "No guest-side USB device/controller signals detected",
        },
        "clipboard_disabled": {
            "passed": True,
            "probes": ["guest_clipboard_agent_probe"],
            "message": "No guest-side shared clipboard agent signals detected",
        },
        "unnecessary_virtual_devices_absent": {
            "passed": True,
            "probes": ["guest_virtual_device_probe"],
            "message": "No guest-side unnecessary virtual device signals detected",
        },
    }


def _apply_guest_probe(tests: dict[str, dict[str, Any]], guest_probe: dict[str, Any]) -> None:
    """Mark failing tests for any guest-side signal in a completed probe."""
    if guest_probe.get("status") != "completed":
        return

    for signal_key, test_name, error_msg in SIGNAL_BINDINGS:
        signals = list(guest_probe.get(signal_key, []))
        if signals:
            tests[test_name].update({"passed": False, "error": f"{error_msg}: {_compact('; '.join(signals))}"})


def main() -> int:
    """Validate OpenNebula virtual-device hardening and emit structured JSON."""
    parser = argparse.ArgumentParser(description="Validate OpenNebula VM virtual-device hardening")
    parser.add_argument("--instance-id", required=True, help="OpenNebula VM ID")
    parser.add_argument("--region", default="", help="(unused) accepted for suite compatibility")
    parser.add_argument("--public-ip", default="", help="SSH host for guest probes")
    parser.add_argument("--key-file", default="", help="SSH private key path for guest probes")
    parser.add_argument("--ssh-user", default="root", help="SSH username")
    parser.add_argument(
        "--ssh-timeout",
        type=int,
        default=60,
        help="Total seconds for the combined guest probe SSH command",
    )
    args = parser.parse_args()

    tests = _base_tests()
    guest_probe_error: str | None = None
    try:
        guest_probe = _collect_guest_probe(args.public_ip, args.ssh_user, args.key_file, args.ssh_timeout)
    except ValueError as e:
        guest_probe_error = _compact(str(e))
        guest_probe = {"status": "unavailable"}
    if guest_probe_error is None and guest_probe.get("status") == "unavailable":
        guest_probe_error = _compact(str(guest_probe.get("error") or "guest probe unavailable"))
    if guest_probe_error is None and guest_probe.get("status") == "skipped":
        guest_probe_error = _compact(str(guest_probe.get("reason") or "guest probe skipped"))

    _apply_guest_probe(tests, guest_probe)

    success = guest_probe_error is None and all(tests[name].get("passed") is True for name in REQUIRED_TESTS)
    result: dict[str, Any] = {
        "success": success,
        "platform": "vm",
        "test_name": "virtual_device_hardening",
        "tests": tests,
    }
    if guest_probe_error is not None:
        result["error"] = guest_probe_error
    print(json.dumps(result, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
