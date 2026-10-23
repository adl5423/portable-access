# Governance

Aisen Lopez Ramos is the initial maintainer. Maintainers decide which changes enter the reference implementation and sign releases. Proposals and decisions are public in repository issues and pull requests. Security reports remain private until coordinated disclosure.

The specification is an open proposal. This repository does not claim IETF status, a platform endorsement, a security certification or universal provider compatibility. Independent implementations and public conformance evidence are needed before making interoperability claims.

A proposal changing a wire format, identity adapter, trust boundary, custody model or revocation guarantee must document compatibility, threat assumptions, failure behavior, migration and tests. A proposal may be rejected when it shifts credential custody into an application, makes authorization ambiguous, or cannot fail closed after state loss.

New maintainers need a history of reviewed contributions, agreement to the security policy, and approval from the current maintainer. Maintainer appointments and removals are recorded in this file through a reviewed pull request. Participants can fork the complete implementation and specification under Apache-2.0.

The reference implementation follows semantic versioning. The version identifies the software release; each wire profile carries its own explicit version. Early profile changes may require migration even when the software remains pre-1.0. Release notes must state the actual compatibility impact.
