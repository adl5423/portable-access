# Development and releases

Use Python 3.12 or newer and Node.js 22 or 24. Linux is required to exercise systemd confinement, peer-UID sockets and memfd transport. macOS can run source tests and native Keychain operator custody; those tests do not prove Linux isolation.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m ruff check .
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q deploy/instabox/tests
.venv/bin/python -m pytest -q examples/docker-https/tests
python3 examples/docker-https/tests/container_acceptance.py
(cd adapters/netlify && npm ci --ignore-scripts && npm run check)
(cd adapters/netlify-seal && npm ci --ignore-scripts && npm run check)
for project in space-briefing charging-briefing science-digest; do
  (cd "examples/$project" && npm ci --ignore-scripts && npm run check)
done
(cd adapters/netlify && node tools/check-python-interop.mjs ../../.venv/bin/python)
```

Use an absolute Python path for the interoperability command if your shell resolves relative executable paths differently. The command creates synthetic keys, verifies Node proofs in Python, and verifies Python signatures in Node. It does not use real API credentials.

CI runs the Python and Docker HTTPS protocol suites on 3.12, 3.13 and 3.14, and the Node adapter and example suites on Node 22 and 24. A separate Docker job builds pinned images and verifies non-root execution, filesystem and capability restrictions, fresh certificate-volume ownership and a trusted local HTTPS gateway. Container acceptance requires a running Docker engine; its uniquely named test resources are removed afterwards. CI also checks public defaults, package versions, dependency audit results and Python/Node signature interoperability. Privileged Linux tests report explicit skips where the runner does not meet the test prerequisites. Review these skips before claiming host isolation acceptance.

Actions use immutable commit pins. Dependabot proposes dependency and action updates; reviewers must verify upstream provenance and rerun validation. CI has read-only repository permissions. Only the release job gets write permission to create a GitHub release. Neither routine CI nor release builds receive application provider keys.

## Build an independent release

Commit the complete reviewed source first. Match the Python package, both adapter package manifests and all example package versions. Refresh every affected lockfile. Run all required checks, then use:

```sh
.venv/bin/python scripts/check-release.py
.venv/bin/python scripts/build-release.py --output dist/release
(cd dist/release && shasum -a 256 -c SHA256SUMS)
```

The build writes a Python wheel and source distribution, the server-only Netlify SDK archive, three standalone Netlify example archives, a standalone Docker HTTPS archive and SHA256SUMS. Each Netlify example archive contains its own SDK package under `vendor/`, its lockfile and a base-independent Netlify configuration. The builder installs and checks each packaged Netlify example before producing its archive. The Docker archive retains the source layout needed by its Compose build context and includes pinned dependency locks, application source and deployment docs. The output directory must be empty to prevent mixing old artifacts into a release.

A `v<package-version>` tag triggers the full CI workflow before publishing those files through GitHub Releases. The tag must match the package version exactly. npm and PyPI publishing are not configured. If the project adopts registries, use their OIDC trusted-publisher workflows and keep registry authorization in a separate reviewed job.

Release checks reject known credential file types, private-key PEM blocks, provider key patterns, enabled example defaults and missing version/license metadata. This catches specific mistakes; it does not replace manual review of the complete public tree and Git history. Never add an operator backup to a public commit, even if encrypted.

## Evidence boundaries

A local test shows only the behavior asserted by that test. A Netlify bundle shows that source can be packaged. Live acceptance requires the expected published production site, authority audit records, two valid protected requests separated beyond the configured credential TTL, and a successful denied-request check. A host reboot requires a separate live recovery check. Preserve private deployment receipts outside the public repository.
