"""Static MITRE ATT&CK technique mapping.

Each telemetry (source, action) pair maps to the ATT&CK technique the
detection most directly evidences. The lookup falls back to a source-wide
default (`(source, "*")`) so new actions from a monitor still get tagged.
"""

def _t(technique_id: str, name: str) -> dict:
    return {
        "id": technique_id,
        "name": name,
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }


TECHNIQUE_MAP: dict[tuple[str, str], dict] = {
    # Reverse shells / blocked interpreters killed by the watchdog
    ("port_watchdog", "killed"): _t("T1059", "Command and Scripting Interpreter"),
    ("port_watchdog", "kill_failed"): _t("T1059", "Command and Scripting Interpreter"),
    # A new unexpected listener is command-and-control staging
    ("port_watchdog", "detected"): _t("T1571", "Non-Standard Port"),
    # DNS-based C2 / malicious domain resolution blocked by the sinkhole
    ("dns_sinkhole", "*"): _t("T1071.004", "Application Layer Protocol: DNS"),
    # ARP spoofing = adversary-in-the-middle
    ("arp_guard", "*"): _t("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning"),
    # Payloads dropped on disk
    ("file_drop", "*"): _t("T1105", "Ingress Tool Transfer"),
    ("quarantine", "quarantined"): _t("T1105", "Ingress Tool Transfer"),
    # Removable media
    ("usb_guard", "*"): _t("T1091", "Replication Through Removable Media"),
    # Agent killed without restarting → defenses tampered with
    ("agent", "device_unresponsive"): _t("T1562.001", "Impair Defenses: Disable or Modify Tools"),
}


def technique_for(source: str, action: str) -> dict | None:
    return TECHNIQUE_MAP.get((source, action)) or TECHNIQUE_MAP.get((source, "*"))
