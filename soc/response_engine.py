"""soc.response_engine - safe recommended actions. Text only; nothing is executed."""

from typing import List

from . import config


def recommend(incident: dict) -> List[str]:
    host = incident.get("host") or "the affected host"
    source_ip = incident.get("source_ip") or "the source (no IP recorded)"
    playbooks = config.INCIDENT_TYPE_PLAYBOOKS.get(incident.get("type"), ["composite"])

    actions: List[str] = []
    for name in playbooks:
        for template in config.RESPONSE_PLAYBOOKS[name]:
            text = template.format(host=host, source_ip=source_ip)
            if text not in actions:
                actions.append(text)
    if incident.get("severity") == "CRITICAL":
        actions.extend(a for a in config.CRITICAL_EXTRA_ACTIONS if a not in actions)
    return actions
