"""Agent configuration.

Loaded from environment variables and an optional local JSON state file that
stores enrollment credentials. The state file is written with restrictive
permissions (owner read/write only) as a basic tamper-resistance measure.
"""
import json
import os
import platform
import socket
from dataclasses import dataclass, field
from pathlib import Path

STATE_DIR = Path(os.environ.get("SG_STATE_DIR", Path.home() / ".silentguard"))
STATE_FILE = STATE_DIR / "agent_state.json"


@dataclass
class AgentConfig:
    server_url: str = os.environ.get("SG_SERVER_URL", "http://127.0.0.1:8000")
    enroll_token: str = os.environ.get("SG_ENROLL_TOKEN", "silentguard-enroll-demo")
    verify_tls: bool = os.environ.get("SG_VERIFY_TLS", "1") != "0"
    poll_interval: float = float(os.environ.get("SG_POLL_INTERVAL", "3"))
    checkin_interval: float = float(os.environ.get("SG_CHECKIN_INTERVAL", "10"))
    hostname: str = field(default_factory=socket.gethostname)
    platform: str = field(default_factory=lambda: f"{platform.system()} {platform.release()}")
    # Detection defaults (extended at runtime by fleet blocklist pushes)
    blocked_domains: set = field(default_factory=lambda: {
        "malware.testing.google.test",
        "evil-phishing.example",
        "c2.badactor.example",
    })
    blocked_processes: set = field(default_factory=lambda: {
        "mimikatz.exe", "nc.exe", "ncat.exe", "meterpreter",
    })
    suspicious_ports: set = field(default_factory=lambda: {4444, 5555, 6666, 1337, 31337})
    allowlisted_processes: set = field(default_factory=lambda: {
        "systemd", "sshd", "svchost.exe", "System", "services.exe", "lsass.exe",
        "wininit.exe", "explorer.exe", "python", "python3", "python.exe",
        "uvicorn", "node", "nginx", "dockerd", "containerd", "chronyd",
        "cupsd", "NetworkManager", "systemd-resolve", "systemd-resolved",
    })
    dry_run: bool = os.environ.get("SG_DRY_RUN", "0") == "1"


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))
    try:
        os.chmod(STATE_FILE, 0o600)
    except OSError:
        pass
