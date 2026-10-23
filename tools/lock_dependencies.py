"""Freeze an already validated environment using upstream PyPI release hashes.

Run after installing/updating this project's dev dependencies in an isolated venv.
This records installed versions and their dependency closure, not a cross-Python resolver.
Review lock changes and test each target platform before release.
"""

import json
import re
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import distribution
from pathlib import Path
from urllib.request import urlopen

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())


def closure(requirements):
    pending = [Requirement(r) for r in requirements]
    expanded, versions = {}, {}
    while pending:
        requirement = pending.pop()
        name = canonicalize_name(requirement.name)
        dist = distribution(name)
        if dist.version not in requirement.specifier:
            raise RuntimeError(f"installed version outside declared range: {name}")
        contexts = {""} | set(requirement.extras)
        previous = expanded.get(name, set())
        if contexts <= previous:
            continue
        expanded[name] = previous | contexts
        versions[name] = dist.version
        for raw in dist.requires or []:
            child = Requirement(raw)
            if child.marker is None or any(child.marker.evaluate({"extra": extra}) for extra in contexts):
                pending.append(child)
    return versions


def release(item):
    name, version = item
    with urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as response:
        data = json.load(response)
    if data["info"]["version"] != version:
        raise RuntimeError("unexpected release metadata")
    hashes = sorted({file["digests"]["sha256"] for file in data["urls"] if not file.get("yanked")})
    if not hashes or not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes):
        raise RuntimeError("missing or invalid release hashes")
    lines = [f"{name}=={version} \\"]
    lines += [
        f"    --hash=sha256:{value}" + (" \\" if i < len(hashes) - 1 else "")
        for i, value in enumerate(hashes)
    ]
    return name, "\n".join(lines) + "\n"


def main():
    runtime = closure(PROJECT["project"]["dependencies"])
    dev = closure(
        PROJECT["project"]["dependencies"]
        + PROJECT["project"]["optional-dependencies"]["dev"]
        + PROJECT["build-system"]["requires"]
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        blocks = dict(pool.map(release, sorted(dev.items())))
    for filename, versions in (("requirements.lock", runtime), ("requirements-dev.lock", dev)):
        header = f"# Validated installed dependency closure, CPython {sys.version_info.major}.{sys.version_info.minor}.\n"
        header += "# Release hashes from PyPI over HTTPS. Regenerate with tools/lock_dependencies.py.\n"
        (ROOT / filename).write_text(header + "\n" + "\n".join(blocks[name] for name in sorted(versions)))
    print(json.dumps({"runtime_packages": len(runtime), "development_packages": len(dev)}))


if __name__ == "__main__":
    main()
