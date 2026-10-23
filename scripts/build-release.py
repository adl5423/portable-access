#!/usr/bin/env python3
"""Build public distributions and independent example archives from a reviewed checkout."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ("space-briefing", "charging-briefing", "science-digest")


def run(*args: str, cwd: Path = ROOT) -> str:
    result = subprocess.run(args, cwd=cwd, check=False, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, args)
    if result.stderr:
        print(result.stderr, end="")
    return result.stdout


def archive(directory: Path, target: Path, epoch: int) -> None:
    with target.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as stream:
                for path in sorted(directory.rglob("*")):
                    if not path.is_file() or path.is_symlink():
                        continue
                    info = stream.gettarinfo(str(path), str(Path(directory.name) / path.relative_to(directory)))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    info.mode = 0o644
                    with path.open("rb") as source:
                        stream.addfile(info, source)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("dist/release"))
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    for directory in [ROOT / "adapters/netlify", ROOT / "adapters/netlify-seal", *(ROOT / "examples" / name for name in OPERATIONS)]:
        if json.loads((directory / "package.json").read_text())["version"] != version:
            parser.error(f"version mismatch: {directory.relative_to(ROOT)}")
    run(sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output))
    run("npm", "ci", "--ignore-scripts", cwd=ROOT / "adapters/netlify")
    run("npm", "run", "check", cwd=ROOT / "adapters/netlify")
    packed = json.loads(run("npm", "pack", "--json", "--pack-destination", str(output), cwd=ROOT / "adapters/netlify"))
    sdk = output / packed[0]["filename"]
    if not sdk.is_file() or sdk.suffix != ".tgz":
        raise RuntimeError("SDK pack output missing")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or run("git", "show", "-s", "--format=%ct").strip())
    tracked = run("git", "ls-files", "-z").split("\0")
    with tempfile.TemporaryDirectory(prefix="pap-release-") as temporary:
        for operation in OPERATIONS:
            directory = Path(temporary) / operation
            prefix = f"examples/{operation}/"
            for name in tracked:
                if not name.startswith(prefix):
                    continue
                relative = Path(name[len(prefix):])
                if relative.is_absolute() or ".." in relative.parts:
                    raise RuntimeError("unsafe source path")
                target = directory / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            readme = directory / "README.md"
            readme.write_text(readme.read_text().replace("../../docs/use-cases.md", f"https://github.com/adl5423/portable-access/blob/v{version}/docs/use-cases.md"))
            vendor = directory / "vendor"
            vendor.mkdir()
            shutil.copyfile(sdk, vendor / sdk.name)
            package = json.loads((directory / "package.json").read_text())
            package["dependencies"]["@portable-access/netlify"] = f"file:vendor/{sdk.name}"
            (directory / "package.json").write_text(json.dumps(package, indent=2) + "\n")
            config = (directory / "netlify.toml").read_text().replace(
                "npm --prefix ../../adapters/netlify ci && npm --prefix ../../adapters/netlify run build && npm run check", "npm run check"
            )
            (directory / "netlify.toml").write_text(config)
            run("npm", "install", "--package-lock-only", "--ignore-scripts", cwd=directory)
            run("npm", "ci", "--ignore-scripts", cwd=directory)
            run("npm", "run", "check", cwd=directory)
            shutil.rmtree(directory / "node_modules")
            shutil.rmtree(directory / "dist")
            (directory / "public/status.json").unlink(missing_ok=True)
            for notice in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
                shutil.copyfile(ROOT / notice, directory / notice)
            archive(directory, output / f"portable-access-{operation}-{version}.tar.gz", epoch)
    # Retain the repository-relative Docker build context in the standalone archive.
    with tempfile.TemporaryDirectory(prefix="pap-docker-release-") as temporary:
        directory = Path(temporary) / f"portable-access-docker-https-{version}"
        required = {"pyproject.toml", "requirements.lock", "requirements-dev.lock", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", ".dockerignore"}
        for name in tracked:
            if not name or not (name in required or name.startswith("pap/") or name.startswith("examples/docker-https/") or name in {"docs/docker-https.md", "docs/identity-adapters.md"}):
                continue
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("unsafe Docker source path")
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        example_readme = directory / "examples/docker-https/README.md"
        example_readme.write_text(example_readme.read_text().replace(
            "../../docs/operator-cli.md",
            f"https://github.com/adl5423/portable-access/blob/v{version}/docs/operator-cli.md",
        ))
        (directory / "README.md").write_text(
            "# Docker HTTPS workload adapter\n\n"
            "Build and run from this archive root using `docker compose -f examples/docker-https/compose.yaml`. "
            "Read `docs/docker-https.md` and configure the disabled public policy before exposing the service. "
            "The authority is a separate deployment. Complete operator and authority instructions are at "
            f"https://github.com/adl5423/portable-access/tree/v{version}.\n"
        )
        archive(directory, output / f"portable-access-docker-https-{version}.tar.gz", epoch)
    checksums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in sorted(output.iterdir()) if path.is_file())
    (output / "SHA256SUMS").write_text(checksums)
    print(f"Built version {version}; checksums: {output / 'SHA256SUMS'}")


if __name__ == "__main__":
    main()
