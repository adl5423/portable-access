# Security policy

## Supported versions and reporting

The maintainer triages security reports for the latest 0.4.x release. Earlier reference versions receive no backported fixes. Report a suspected vulnerability privately through [GitHub private vulnerability reporting](https://github.com/adl5423/portable-access/security/advisories/new). Maintainer: Aisen Lopez Ramos, GitHub @adl5423. Do not include real credentials, private recovery packets, customer data or unredacted proofs in an issue. A response-time or paid support commitment is not implied.

## Scope

Review identity admission, authorization, tenant/environment isolation, proof replay, credential lifecycle, revocation, encrypted custody, process isolation, TLS trust, administrative peer identity, upstream request validation, retry safety and release integrity. The [threat model](docs/threat-model.md) and [production profile](docs/production-profile.md) define the intended boundaries.

The production command requires a nonroot Linux process with no capabilities and no-new-privileges, a separate administrative UID and an external signer. Public configuration contains no bearer-secret or local-signing fallback. Online authorization fails closed when state or KMS is unavailable. Local demos use a shared UID and do not prove production isolation.

Netlify admission binds an entire trusted production site. Code deployed by an application-site administrator can use that site's configured grant. It does not attest a particular commit or function. Seal custody uses a different trusted project. Custody deployment access, private Blobs access and the provider are part of the root trust boundary. Host root and the KMS administrator can compromise custody. This reference claims neither hardware attestation nor HSM isolation.

The optional provider broker decrypts upstream API keys inside the isolated authority process for a fixed allowed call. Applications never receive those keys. Compromise of the authority can expose decrypted provider credentials. The fixed broker rejects caller-controlled URLs, models, prompts and tools. Durable paid-job claims prevent automatic duplicate generation within the same grant/operation/UTC-hour, including uncertain outcomes. Read docs/connectors.md for cache, revocation and billing semantics.

## Generic HTTPS origin adapter

The `https-origin` identity adapter proves control of the exact public HTTPS origin registered by an operator. DNS, TLS termination, routing, administrators and every application deployment able to publish the proof path belong to this trust boundary. It does not attest a hosting provider, container image or hardware. The identity adapter is an immutable grant binding; changing it requires a fresh registration. Existing registrations without this field retain the Netlify verifier.

The generic client keeps ephemeral proof keys and expiring public records in one process. Its callback accepts read requests only. It exposes no HTTP challenge-publication API. Horizontal replicas need shared proof publication with tested consistency; the supplied memory store provides no cross-process guarantee. Arbitrary public origins still require explicit root-owned registration and the verifier rejects private DNS destinations, redirects and alternative URL spellings.

## Lifecycle and operations

Short-lived workload credentials, proof keys, signing generations and enrollment leaves renew automatically. Pause recovery depends on authenticated time reacquisition and network availability. A provider cold boot is a different event; the independent boot profile retrieves the externally held seal key and unseals OpenBao. It retains plaintext seal material only in protected tmpfs and systemd credentials. Provider roots, enrollment CAs and operator trust require separate lifecycle management. No generic upstream API permits automatic rotation of every provider key.

No independent security audit, full restore certification, HA guarantee, load benchmark or availability SLO is claimed. Before customer production use, complete an isolated encrypted-backup restoration, audit retention, capacity and alert configuration, policy review, actual runtime boundary checks and pause/cold-boot acceptance.

## Change requirements

Security-sensitive changes need adversarial and integration checks. Never log credential values, DPoP proofs, private keys, authorization headers or raw exceptions containing provider responses. Keep credentials out of environment variables, command arguments, public configuration and build artifacts. Dependency locks and CI checks complement code review; passing tests alone does not certify a deployment.
