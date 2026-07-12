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
REPUTATION_FILE = STATE_DIR / "reputation.json"
# Durable offline telemetry spool: events survive an agent restart during a
# connectivity gap so nothing is lost.
QUEUE_FILE = STATE_DIR / "telemetry_queue.json"

# SHA-256 of the EICAR standard antivirus test file — a safe, universally
# recognized "known bad" for demos and tests.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@dataclass
class AgentConfig:
    server_url: str = os.environ.get("SG_SERVER_URL", "http://127.0.0.1:8000")
    enroll_token: str = os.environ.get("SG_ENROLL_TOKEN", "silentguard-enroll-demo")
    verify_tls: bool = os.environ.get("SG_VERIFY_TLS", "1") != "0"
    poll_interval: float = float(os.environ.get("SG_POLL_INTERVAL", "3"))
    checkin_interval: float = float(os.environ.get("SG_CHECKIN_INTERVAL", "10"))
    inventory_interval: float = float(os.environ.get("SG_INVENTORY_INTERVAL", "300"))
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
    # File hash reputation: known-bad executable hashes and a user-maintained
    # allowlist of hashes that must never be quarantined. Extended at startup
    # from REPUTATION_FILE ({"known_bad": [...], "allowlist": [...]}).
    known_bad_hashes: set = field(default_factory=lambda: {EICAR_SHA256})
    allowlisted_hashes: set = field(default_factory=set)
    # Directories watched by the file-drop monitor for newly dropped payloads.
    file_drop_dirs: list = field(default_factory=lambda: [
        p for p in ("/tmp", str(Path.home() / "Downloads")) if Path(p).is_dir()
    ])
    # USB policy: when True, newly inserted USB mass-storage devices are
    # blocked (best effort) instead of just reported.
    block_usb_storage: bool = os.environ.get("SG_BLOCK_USB_STORAGE", "0") == "1"
    # Signed agent updates (M15a): trust key(s) an update manifest must be
    # signed with. Ed25519 public key (hex/base64) is preferred; an HMAC shared
    # secret is a dependency-free fallback. When require_signed_updates is on
    # (default), an update carrying a url/sha256 manifest is honored only with a
    # valid signature; a version-only acknowledgement stays best-effort.
    update_public_key: str = os.environ.get("SG_UPDATE_PUBLIC_KEY", "")
    update_hmac_key: str = os.environ.get("SG_UPDATE_HMAC_KEY", "")
    require_signed_updates: bool = os.environ.get("SG_REQUIRE_SIGNED_UPDATES", "1") != "0"

    def __post_init__(self) -> None:
        rep = load_reputation()
        self.known_bad_hashes.update(rep.get("known_bad", []))
        self.allowlisted_hashes.update(rep.get("allowlist", []))


def load_reputation() -> dict:
    """User-maintained hash reputation extras: {"known_bad": [...], "allowlist": [...]}."""
    try:
        data = json.loads(REPUTATION_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


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


def load_queue() -> list:
    """Load the persisted offline telemetry spool (empty on any error)."""
    try:
        data = json.loads(QUEUE_FILE.read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_queue(events: list) -> None:
    """Persist the offline telemetry spool (best-effort, owner-only perms)."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        QUEUE_FILE.write_text(json.dumps(events))
        os.chmod(QUEUE_FILE, 0o600)
    except OSError:
        pass
