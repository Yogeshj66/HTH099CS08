"""
USB Trust Sub-Score Module (REAL DATA VERSION - Windows)
-------------------------------------------------------------
Pulls real live USB device data using Windows' built-in PowerShell
Get-PnpDevice cmdlet.
"""

import subprocess
import json
import re
import os
import pickle

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "usb_rf_model.pkl")

KNOWN_VENDOR_IDS = {
    "2B7E",
    "13D3",
    "30FA",
}


def load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return None


def _run_powershell(command):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True, text=True, shell=False
    )
    return result.stdout


def _extract_vid_pid(instance_id):
    vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", instance_id)
    pid_match = re.search(r"PID_([0-9A-Fa-f]{4})", instance_id)
    vid = vid_match.group(1) if vid_match else None
    pid = pid_match.group(1) if pid_match else None
    return vid, pid


def capture_devices():
    command = (
        "Get-PnpDevice -PresentOnly | "
        "Where-Object { $_.InstanceId -like 'USB*' } | "
        "Select-Object FriendlyName, Class, Status, InstanceId | "
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
        instance_id = entry.get("InstanceId", "")
        vid, pid = _extract_vid_pid(instance_id)
        devices.append({
            "name": entry.get("FriendlyName") or "Unknown device",
            "device_class": (entry.get("Class") or "unknown").lower(),
            "status": entry.get("Status", "Unknown"),
            "vendor_id": vid,
            "product_id": pid,
            "known_device": vid in KNOWN_VENDOR_IDS if vid else False,
        })

    return devices


def rule_based_score(devices):
    score = 100
    flags = []

    if not devices:
        flags.append("No USB devices detected")
        return score, flags

    hid_devices = [d for d in devices if d["device_class"] in ("hidclass", "keyboard", "mouse")]
    storage_devices = [d for d in devices if d["device_class"] in ("diskdrive",)]

    for dev in devices:
        if dev["status"] != "OK":
            score -= 15
            flags.append(f"{dev['name']} - device status: {dev['status']}")

        if not dev["known_device"] and dev["vendor_id"]:
            score -= 5
            flags.append(f"Unrecognized vendor for '{dev['name']}' (VID {dev['vendor_id']})")

    if len(hid_devices) > 0 and len(storage_devices) > 0:
        score -= 20
        flags.append("HID device(s) present alongside storage device(s) - review for BadUSB pattern")

    if not flags:
        flags.append(f"{len(devices)} USB device(s) connected - no issues detected")

    return max(0, min(100, score)), flags


def get_usb_subscore():
    model = load_model()
    devices = capture_devices()
    score, flags = rule_based_score(devices)

    return {
        "module": "usb",
        "score": score,
        "flags": flags,
        "raw_devices": devices,
    }


if __name__ == "__main__":
    print(json.dumps(get_usb_subscore(), indent=2))