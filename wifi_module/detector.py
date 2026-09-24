"""
Wi-Fi Trust Sub-Score Module (REAL DATA VERSION - Windows)
-------------------------------------------------------------
Pulls real live Wi-Fi data using Windows' built-in `netsh wlan` command.
No special Wi-Fi adapter or monitor-mode drivers needed — works on any
Windows laptop out of the box.
"""

import subprocess
import re
import os
import pickle

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "wifi_rf_model.pkl")


def load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return None


def _run_netsh(args):
    """Run a netsh wlan command and return stdout as text."""
    result = subprocess.run(
        ["netsh", "wlan"] + args,
        capture_output=True, text=True, shell=False
    )
    return result.stdout


def get_connected_network():
    """Returns info about the network this PC is currently connected to."""
    output = _run_netsh(["show", "interfaces"])
    info = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSID") and "BSSID" not in line:
            info["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("BSSID"):
            info["bssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("Signal"):
            sig = line.split(":", 1)[1].strip().replace("%", "")
            info["signal_percent"] = int(sig) if sig.isdigit() else None
        elif line.startswith("Radio type"):
            info["radio_type"] = line.split(":", 1)[1].strip()
        elif line.startswith("Authentication"):
            info["auth"] = line.split(":", 1)[1].strip()
        elif line.startswith("Cipher"):
            info["cipher"] = line.split(":", 1)[1].strip()
        elif line.startswith("Channel"):
            info["channel"] = line.split(":", 1)[1].strip()
    return info


def get_all_visible_networks():
    """
    Returns a list of all nearby networks with their SSIDs, BSSIDs, and
    signal strength — used to detect duplicate-SSID / evil-twin patterns.
    """
    output = _run_netsh(["show", "networks", "mode=bssid"])
    networks = []
    current = None

    for line in output.splitlines():
        line = line.rstrip()
        ssid_match = re.match(r"^SSID \d+ : (.*)$", line.strip())
        bssid_match = re.match(r"^BSSID \d+\s*:\s*(.*)$", line.strip())
        signal_match = re.match(r"^Signal\s*:\s*(\d+)%$", line.strip())
        auth_match = re.match(r"^Authentication\s*:\s*(.*)$", line.strip())

        if ssid_match:
            current = {"ssid": ssid_match.group(1).strip(), "bssids": []}
            networks.append(current)
        elif bssid_match and current is not None:
            current["bssids"].append({"bssid": bssid_match.group(1).strip()})
        elif signal_match and current is not None and current["bssids"]:
            current["bssids"][-1]["signal"] = int(signal_match.group(1))
        elif auth_match and current is not None:
            current["auth"] = auth_match.group(1).strip()

    return networks


def capture_features():
    """
    Real feature capture using netsh. Returns the same feature dict shape
    the rest of the module expects, built from actual live Wi-Fi data.
    """
    connected = get_connected_network()
    all_networks = get_all_visible_networks()

    auth = connected.get("auth", "").lower()
    if "wpa3" in auth:
        encryption = "WPA3"
    elif "wpa2" in auth:
        encryption = "WPA2"
    elif "wep" in auth:
        encryption = "WEP"
    elif "open" in auth:
        encryption = "Open"
    else:
        encryption = auth.upper() if auth else "Unknown"

    bssid_mismatch = 0
    signal_variance = 0.0
    connected_ssid = connected.get("ssid", "")
    for net in all_networks:
        if net["ssid"] == connected_ssid and len(net["bssids"]) > 1:
            signals = [b["signal"] for b in net["bssids"] if "signal" in b]
            if signals:
                signal_variance = round((max(signals) - min(signals)) / 10, 2)
            bssid_mismatch = 1

    features = {
        "ssid": connected_ssid or "Not connected",
        "encryption": encryption,
        "signal_variance": signal_variance,
        "bssid_mismatch": bssid_mismatch,
        "signal_percent": connected.get("signal_percent", 0),
        "deauth_packets_detected": 0,
    }
    return features


def rule_based_score(features):
    score = 100
    flags = []

    enc = features["encryption"]
    if enc == "Open":
        score -= 40
        flags.append("Open network — no encryption")
    elif enc == "WEP":
        score -= 30
        flags.append("WEP encryption is broken/outdated")
    elif enc == "WPA2":
        score -= 10
        flags.append("WPA2 in use — consider WPA3")
    elif enc == "Unknown":
        score -= 15
        flags.append("Could not determine encryption type")

    if features["signal_variance"] > 3:
        score -= 15
        flags.append("Same SSID seen with inconsistent signal across BSSIDs (possible evil twin)")

    if features["bssid_mismatch"]:
        score -= 10
        flags.append("Same SSID broadcast by multiple access points nearby")

    if features["signal_percent"] and features["signal_percent"] < 30:
        score -= 5
        flags.append("Weak connection signal")

    if not flags:
        flags.append(f"Connected to '{features['ssid']}' — no issues detected")

    return max(0, min(100, score)), flags


def get_wifi_subscore() -> dict:
    """Public entry point used by the fusion layer."""
    model = load_model()
    features = capture_features()
    score, flags = rule_based_score(features)

    return {
        "module": "wifi",
        "score": score,
        "flags": flags,
        "raw_features": features,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(get_wifi_subscore(), indent=2))