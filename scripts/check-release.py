#!/usr/bin/env python3
"""Reject credential files, unsafe demo defaults and incomplete release metadata."""
from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
failures: list[str] = []
for name in filter(None, tracked):
    path = Path(name)
    if any(part in {"node_modules", ".netlify", ".venv", "operator-private", "verification"} for part in path.parts) or path.suffix in {".pem", ".key", ".sqlite", ".whl", ".tgz"} or name.endswith((".enc.json", ".creation.json")) or path.name.startswith(".env") and path.name != ".env.example":
        failures.append(f"private/build file tracked: {name}")
        continue
    if (root / path).is_symlink():
        failures.append(f"source symlink requires review: {name}")
        continue
    content = (root / path).read_bytes()
    if (b"-----BEGIN " + b"PRIVATE KEY-----") in content or (b"-----BEGIN RSA " + b"PRIVATE KEY-----") in content or re.search(rb"sk-(?:proj-)?[A-Za-z0-9_-]{40,}", content):
        failures.append(f"credential-shaped material tracked: {name}")
for path in root.glob("**/src/config.public.json"):
    if "node_modules" in path.parts or "dist" in path.parts:
        continue
    config = json.loads(path.read_text())
    if config.get("enabled") is not False:
        failures.append(f"enabled public default: {path.relative_to(root)}")
    if "productionSiteIsolated" in config and config["productionSiteIsolated"] is not False:
        failures.append(f"unprovisioned site claims isolation: {path.relative_to(root)}")
version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
for path in [root / "adapters/netlify/package.json", root / "adapters/netlify-seal/package.json", *root.glob("examples/*/package.json")]:
    if json.loads(path.read_text())["version"] != version:
        failures.append(f"version mismatch: {path.relative_to(root)}")
for name in ["LICENSE", "NOTICE", "README.md", "SECURITY.md", "CONTRIBUTING.md", "GOVERNANCE.md", "CHANGELOG.md"]:
    if not (root / name).is_file():
        failures.append(f"missing release document: {name}")
if failures:
    raise SystemExit("\n".join(failures))
print("Public source/default/version checks passed. This is one release check, not a guarantee that no secret exists.")
