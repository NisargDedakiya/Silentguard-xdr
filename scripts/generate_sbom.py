#!/usr/bin/env python3
"""Generate a CycloneDX-style SBOM (JSON) from the installed Python packages.

Usage:
    python scripts/generate_sbom.py > sbom.json

No third-party dependencies: reads installed distributions via
importlib.metadata. Intended for supply-chain visibility of the server/agent
runtime (M21).
"""
import datetime
import json
import sys
from importlib import metadata


def build_sbom() -> dict:
    components = []
    for dist in sorted(metadata.distributions(),
                       key=lambda d: (d.metadata["Name"] or "").lower()):
        name = dist.metadata["Name"]
        if not name:
            continue
        components.append({
            "type": "library",
            "name": name,
            "version": dist.version,
            "purl": f"pkg:pypi/{name.lower()}@{dist.version}",
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "component": {"type": "application", "name": "silentguard-xdr"},
        },
        "components": components,
    }


if __name__ == "__main__":
    json.dump(build_sbom(), sys.stdout, indent=2)
    sys.stdout.write("\n")
