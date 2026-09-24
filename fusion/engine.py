"""
Fusion Layer — Unified Trust Score Engine
--------------------------------------------
Combines Wi-Fi, USB, and Bluetooth sub-scores into one final trust score.

This is the "novel contribution" piece for your IEEE paper: a weighted
multi-vector fusion instead of single-attack-surface scoring.

Weights are fixed for v1 (justify these in your paper based on relative
attack severity/likelihood). Swap in a learned meta-model later if you want
to claim it as "future work" -> "implemented work".
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from wifi_module.detector import get_wifi_subscore
from usb_module.detector import get_usb_subscore
from bluetooth_module.scanner import get_bluetooth_subscore

WEIGHTS = {
    "wifi": 0.40,
    "usb": 0.35,
    "bluetooth": 0.25,
}


def compute_trust_score():
    wifi = get_wifi_subscore()
    usb = get_usb_subscore()
    bt = get_bluetooth_subscore()

    final_score = (
        wifi["score"] * WEIGHTS["wifi"]
        + usb["score"] * WEIGHTS["usb"]
        + bt["score"] * WEIGHTS["bluetooth"]
    )
    final_score = round(final_score, 1)

    # Rank sub-scores by how much they're dragging the final score down —
    # this doubles as a lightweight "explainability" layer even before you
    # wire in real SHAP values on the Wi-Fi RF model.
    contributions = sorted(
        [
            {"module": "wifi", "score": wifi["score"], "weight": WEIGHTS["wifi"], "flags": wifi["flags"]},
            {"module": "usb", "score": usb["score"], "weight": WEIGHTS["usb"], "flags": usb["flags"]},
            {"module": "bluetooth", "score": bt["score"], "weight": WEIGHTS["bluetooth"], "flags": bt["flags"]},
        ],
        key=lambda x: x["score"],
    )

    if final_score >= 80:
        status = "Trusted"
    elif final_score >= 50:
        status = "Caution"
    else:
        status = "Untrusted"

    return {
        "final_score": final_score,
        "status": status,
        "sub_scores": {
            "wifi": wifi,
            "usb": usb,
            "bluetooth": bt,
        },
        "contributions_ranked": contributions,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(compute_trust_score(), indent=2))
