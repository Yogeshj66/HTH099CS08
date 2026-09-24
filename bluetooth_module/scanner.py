"""
Bluetooth Trust Sub-Score Module (REAL DATA VERSION - Hybrid)
-------------------------------------------------------------------
Covers BLE nearby scan (bleak) + classic paired devices (PowerShell).
"""

import asyncio
import subprocess
import json

try:
    from bleak import BleakScanner
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

KNOWN_DEVICE_NAMES = {
    "Airdopes 155",
    "Airdopes 155 Avrcp Transport",
    "ZEB-THUNDER",
    "ZEB-THUNDER Avrcp Transport",
    "AirPods Pro",
    "AirPods Pro Avrcp Transport",
    "Service Discovery Service",
    "Bluetooth Device (RFCOMM Protocol TDI)",
}


async def _scan_ble(timeout=6.0):
    devices = await BleakScanner.discover(timeout=timeout)
    results = []
    for d in devices:
        rssi = getattr(d, "rssi", None) or getattr(d, "_rssi", None)
        results.append({"name": d.name or "Unknown", "address": d.address, "rssi": rssi, "source": "ble"})
    return results


def capture_ble_devices():
    if not BLEAK_AVAILABLE:
        return []
    try:
        return asyncio.run(_scan_ble())
    except Exception as e:
        print(f"[bluetooth_module] BLE scan failed: {e}")
        return []


def _run_powershell(command):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True, text=True, shell=False
    )
    return result.stdout


def capture_classic_devices():
    command = (
        "Get-PnpDevice -Class Bluetooth -PresentOnly | "
        "Select-Object FriendlyName, Status, InstanceId | "
        "ConvertTo-Json -Compress"
    )
    output = _run_powershell(command)

    devices = []
    if not output.strip():
        return devices

    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return devices

    if isinstance(parsed, dict):
        parsed = [parsed]

    for entry in parsed:
        name = entry.get("FriendlyName") or "Unknown Bluetooth device"
        if "Enumerator" in name or "Radio" in name or "Adapter" in name:
            continue
        devices.append({
            "name": name,
            "address": entry.get("InstanceId", ""),
            "rssi": None,
            "source": "classic",
            "status": entry.get("Status", "Unknown"),
        })

    return devices


def rule_based_score(devices):
    score = 100
    flags = []

    if not devices:
        flags.append("No Bluetooth devices found (BLE nearby or classic paired)")
        return score, flags

    for dev in devices:
        if dev["name"] not in KNOWN_DEVICE_NAMES:
            score -= 5
            flags.append(f"Unrecognized {dev['source']} device: {dev['name']}")

        if dev.get("rssi") is not None and dev["rssi"] < -85:
            flags.append(f"Very weak signal from {dev['name']} (RSSI {dev['rssi']}) - possible spoof/relay")

        if dev.get("status") and dev["status"] != "OK":
            score -= 10
            flags.append(f"{dev['name']} - status: {dev['status']}")

    score = max(0, min(100, score))

    if not flags:
        flags.append(f"{len(devices)} known Bluetooth device(s) - no issues detected")

    return score, flags


def get_bluetooth_subscore():
    ble_devices = capture_ble_devices()
    classic_devices = capture_classic_devices()
    all_devices = ble_devices + classic_devices

    score, flags = rule_based_score(all_devices)

    return {
        "module": "bluetooth",
        "score": score,
        "flags": flags,
        "raw_devices": all_devices,
    }


if __name__ == "__main__":
    print(json.dumps(get_bluetooth_subscore(), indent=2))