# Contributing

PAP is an Apache-2.0 protocol proposal and reference implementation. Contributions to code, deployment tools, documentation and public test vectors are welcome. The maintainer reviews security properties and operational failure modes before adding an adapter.

Read [the development guide](docs/development.md), [the security policy](SECURITY.md), and the relevant profile before changing code. A passing unit suite is necessary, but cannot establish platform identity, process confinement or live cloud acceptance.

Use an issue for a proposed behavioral or wire-format change. State the problem, affected trust boundary, compatibility impact and expected denial behavior. Do not include tokens, credentials, private recovery packets, customer data or unredacted production logs. Report vulnerabilities through the private channel in SECURITY.md.

Each commit must include a Developer Certificate of Origin sign-off. Use `git commit -s` after reading [DCO 1.1](https://developercertificate.org/). The sign-off certifies your right to submit the change under this project's license; it does not transfer copyright. Contributions use Apache-2.0 unless an existing third-party file explicitly states otherwise.

Keep changes scoped. Add tests for changed authorization rules, parsing, replay behavior, recovery state transitions and durable paid-operation claims. Update the relevant profile and operator guide when behavior changes. Avoid tests that merely restate a low-impact implementation detail. Describe the actual validation performed in the pull request.

Maintainers will not merge a change that logs secrets, requires application environment secrets for the PAP profile, silently broadens grants, retries an uncertain paid operation, or labels a local result as verified production behavior.
