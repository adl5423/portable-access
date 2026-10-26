"""Supported operator CLI. Output contains public receipts only."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .custody import (
    CustodyError,
    EncryptedPEMCustody,
    MacOSKeychainCustody,
    private_read,
    public_jwk,
    public_pin,
    public_read,
    read_passphrase,
    trusted_public_path,
    write_new_private,
)
from .envelope import (
    MAX_PACKET,
    canonical,
    decode,
    decrypt_openai_backup,
    decrypt_packet,
    encrypt_packet,
    inspect_packet,
    parse_json,
    prepare_successor,
    recovery_material,
    static_seal_material,
)
from .kms import provision_kms
from .process import harden_process
from .transport import OpenBaoOperator, import_credential, memfd_mtls, ssh_command, ssh_send
from .workloads import WorkloadSetupError, check_workload_files, create_workload


def load_custody(metadata_path: Path, passphrase_fd: int | None = None):
    harden_process()
    metadata = parse_json(private_read(metadata_path))
    backend = metadata.get("backend")
    # Existing native metadata predates the public CLI and has no backend field.
    if backend == "keychain" or backend is None and "application_tag" in metadata:
        custody = MacOSKeychainCustody(metadata["application_tag"])
    elif backend == "encrypted-pem":
        private_file = metadata.get("private_key_file", "operator-private.pem")
        if not isinstance(private_file, str) or Path(private_file).name != private_file:
            raise CustodyError("Private key filename must be relative to custody metadata")
        custody = EncryptedPEMCustody(metadata_path.parent / private_file, read_passphrase(passphrase_fd))
    else:
        raise CustodyError("Unsupported operator custody backend")
    expected_pin = metadata.get("public_key_sha256")
    if not isinstance(expected_pin, str) or expected_pin != public_pin(custody.public_der()):
        raise CustodyError("Operator custody public key pin mismatch")
    return custody


def _expected(args) -> dict[str, str]:
    expected = {"machine_id": args.machine_id, "host_identity_sha256": args.host_identity_sha256}
    if getattr(args, "stage", None):
        expected["stage"] = args.stage
    return expected


def _read_packet(args, custody):
    raw = private_read(args.packet, MAX_PACKET)
    return raw, decrypt_packet(raw, custody, expected=_expected(args), expected_sha256=args.envelope_sha256)


def _ssh(args, operation: str, payload: dict, *, maximum=1024 * 1024) -> bytes:
    arguments = [operation]
    if operation == "receive-credential":
        arguments.extend(
            ["--socket", str(args.socket), "--admin-user", args.admin_user, "--issuer-user", args.issuer_user]
        )
    command = ssh_command(
        args.target,
        executable=args.remote_executable,
        arguments=arguments,
        port=args.ssh_port,
        known_hosts=args.known_hosts,
    )
    return ssh_send(command, payload, maximum=maximum)


def _secret_fd(fd: int) -> bytes:
    if fd < 3:
        raise CustodyError("Secret FD must be a separate inherited descriptor, at least 3")
    value = os.read(fd, 4097).rstrip(b"\r\n")
    if not 1 <= len(value) <= 4096 or any(c < 33 or c > 126 for c in value):
        raise CustodyError("Provider credential must be bounded printable ASCII")
    return value


def _receiver_input() -> dict:
    harden_process()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise CustodyError("Secret receivers require root on the dedicated Linux host")
    if sys.stdin.isatty():
        raise CustodyError("Secret receiver requires its authenticated SSH input stream")
    return parse_json(sys.stdin.buffer.read(MAX_PACKET + 1))


def _import_as_admin(args, payload: dict) -> dict:
    import pwd

    try:
        admin = pwd.getpwnam(args.admin_user)
        issuer = pwd.getpwnam(args.issuer_user)
    except KeyError as exc:
        raise CustodyError("Dedicated authority admin and issuer accounts are required") from exc
    if min(admin.pw_uid, issuer.pw_uid) <= 0 or admin.pw_uid == issuer.pw_uid:
        raise CustodyError("Admin and issuer must be distinct unprivileged accounts")
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(admin.pw_gid)
        os.setuid(admin.pw_uid)
    if os.geteuid() != admin.pw_uid:
        raise CustodyError("Credential import requires the dedicated admin identity")
    return import_credential(
        args.socket, payload, expected_peer_uid=issuer.pw_uid, expected_socket_uid=admin.pw_uid
    )


def _receiver_recovery(value: dict) -> dict:
    if set(value) != {"packet", "machine_id", "host_identity_sha256"}:
        raise CustodyError("Invalid recovery transport members")
    local_hash = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    if value["host_identity_sha256"] != local_hash:
        raise CustodyError("Recovery transport targets a different Linux host")
    packet = value["packet"]
    material = recovery_material(packet)
    if (
        material.get("machine_id") != value["machine_id"]
        or material.get("host_identity_sha256") != local_hash
    ):
        raise CustodyError("Recovery packet host binding mismatch")
    return packet


def execute(args) -> dict | None:
    if args.command == "workload-init":
        return create_workload(
            adapter=args.adapter, issuer=args.issuer, audience=args.audience, origin=args.origin,
            tenant=args.tenant, output_directory=args.output_directory, workload_id=args.workload_id,
            grant_days=args.grant_days, resource_path=args.resource_path, resource_action=args.resource_action,
            enabled=args.enable, trust_origin=args.trust_origin,
        )
    if args.command == "workload-check":
        return check_workload_files(
            args.config, args.registration, authority_path=args.authority_config,
            require_ready=args.require_ready,
        )
    if args.command == "custody-create":
        directory = args.directory
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if any(
            (directory / name).exists()
            for name in ("keychain-key.json", "operator-public.der", "operator-private.pem")
        ):
            raise CustodyError("Custody destination already contains key material")
        if args.backend == "keychain":
            tag = args.application_tag or "org.portable-access.operator." + uuid.uuid4().hex
            custody = MacOSKeychainCustody.create(tag)
            metadata = {
                "backend": "keychain",
                "application_tag": tag,
                "private_key_location": "macOS Keychain, nonextractable software RSA",
            }
        else:
            custody = EncryptedPEMCustody.create(
                directory / "operator-private.pem", read_passphrase(args.passphrase_fd, confirm=True)
            )
            metadata = {"backend": "encrypted-pem", "private_key_file": "operator-private.pem"}
        der = custody.public_der()
        metadata.update(
            {
                "schema": "pap-operator-custody-v1",
                "public_key_sha256": public_pin(der),
                "public_key_file": "operator-public.der",
                "created_at": datetime.now(UTC).isoformat(),
            }
        )
        write_new_private(directory / "operator-public.der", der)
        write_new_private(directory / "keychain-key.json", canonical(metadata) + b"\n")
        return {
            "created": True,
            "backend": args.backend,
            "public_key_sha256": public_pin(der),
            "metadata": str(directory / "keychain-key.json"),
        }
    if args.command == "inspect":
        return inspect_packet(private_read(args.packet, MAX_PACKET))
    if args.command == "receive-credential":
        payload = _receiver_input()
        action = payload.get("action")
        members = {"provider", "action", "credential"} if action == "import" else {"provider", "action"}
        if (
            set(payload) != members
            or payload.get("provider") not in ("openai", "nasa", "nlr")
            or action not in ("import", "revoke")
        ):
            raise CustodyError("Invalid credential transport request")
        if action == "import" and (
            not isinstance(payload["credential"], str) or not 1 <= len(payload["credential"]) <= 4096
        ):
            raise CustodyError("Invalid credential transport request")
        return _import_as_admin(args, payload)
    if args.command in ("receive-unseal", "receive-snapshot", "receive-kms-provision"):
        received = _receiver_input()
        options = received.pop("options", {}) if args.command == "receive-kms-provision" else {}
        if (
            not isinstance(options, dict)
            or set(options) - {"apply", "expected_plan_sha256"}
            or type(options.get("apply", False)) is not bool
        ):
            raise CustodyError("Invalid KMS provisioning options")
        packet = _receiver_recovery(received)
        with memfd_mtls(packet) as context:
            operator = OpenBaoOperator(context)
            if args.command == "receive-kms-provision":
                return provision_kms(operator, **options)
            if args.command == "receive-unseal":
                return operator.unseal(packet)
            snapshot = operator.snapshot()
        if len(snapshot) > 8 * 1024 * 1024:
            raise CustodyError("Snapshot exceeds the operator packet limit; use the large-backup runbook")
        # The snapshot travels inside authenticated SSH and is encrypted by the
        # operator before it is persisted. No credentials appear in this output.
        sys.stdout.buffer.write(snapshot)
        return None
    if args.command == "credential-revoke":
        payload = {"provider": args.provider, "action": "revoke"}
        return (
            parse_json(_ssh(args, "receive-credential", payload))
            if args.target
            else _import_as_admin(args, payload)
        )
    custody = load_custody(args.custody, args.passphrase_fd)
    if args.command == "public":
        der = custody.public_der()
        return {"public_key_sha256": public_pin(der), "jwk": public_jwk(der)}
    if args.command == "credential-import":
        if args.encrypted_openai_backup is not None:
            if args.provider != "openai" or not args.name or not args.organization_id or not args.project_id:
                raise CustodyError("Encrypted OpenAI import requires name, organization and project bindings")
            secret = decrypt_openai_backup(
                private_read(args.encrypted_openai_backup, 1024 * 1024),
                custody,
                name=args.name,
                organization_id=args.organization_id,
                project_id=args.project_id,
            )
        else:
            secret = _secret_fd(args.secret_fd)
        payload = {"provider": args.provider, "action": "import", "credential": secret.decode("ascii")}
        return (
            parse_json(_ssh(args, "receive-credential", payload))
            if args.target
            else _import_as_admin(args, payload)
        )
    raw, packet = _read_packet(args, custody)
    if args.command == "custody-provision":
        if not 3 <= args.netlify_token_fd <= 65535:
            raise CustodyError(
                "Custody provisioning requires a verified static-seal successor and separate provider token FD"
            )
        config = parse_json(public_read(args.config, 65536), 65536)
        deployment_id, secret = static_seal_material(packet)
        key_id = hashlib.sha256(secret).hexdigest()
        aad = inspect_packet(raw)["aad"]
        if (
            config.get("key_id") != key_id
            or aad.get("static_seal_key_id") != key_id
            or config.get("machine_id") != args.machine_id
            or deployment_id != config.get("deployment_id")
        ):
            raise CustodyError("Custody public configuration does not match the durable encrypted successor")
        record = {
            "v": 1,
            "enabled": True,
            "deployment_id": config["deployment_id"],
            "machine_id": args.machine_id,
            "origin": config["origin"],
            "key_id": key_id,
            "key_b64url": base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii"),
        }
        helper = args.helper.absolute()
        trusted_public_path(helper)
        node = shutil.which("node")
        if node is None:
            raise CustodyError("Node.js is required for the independent Netlify custody helper")
        env = {
            name: value
            for name, value in os.environ.items()
            if name in {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL"}
        }
        try:
            completed = subprocess.run(
                [
                    node,
                    str(helper),
                    "--config",
                    str(args.config.absolute()),
                    "--token-fd",
                    str(args.netlify_token_fd),
                ],
                input=canonical(record),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                pass_fds=(args.netlify_token_fd,),
                env=env,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CustodyError(
                "Custody provisioning outcome unknown; inspect private record before retrying"
            ) from exc
        if completed.returncode != 0 or len(completed.stdout) > 65536:
            raise CustodyError(
                "Custody provisioning failed or outcome unknown; inspect protected provider state before retrying"
            )
        result = parse_json(completed.stdout, 65536)
        expected_receipt = {
            "v": 1,
            "operation": "provision",
            "store": "pap-seal-custody-v1",
            "site_id": config["site_id"],
            "deployment_id": config["deployment_id"],
            "key_id": key_id,
            "enabled": True,
            "record_sha256": hashlib.sha256(canonical(record)).hexdigest(),
        }
        if (
            set(result) != {*expected_receipt, "state"}
            or any(result.get(key) != value for key, value in expected_receipt.items())
            or result.get("state") not in ("created", "unchanged")
        ):
            raise CustodyError(
                "Custody provisioning receipt verification failed; inspect protected provider state before retrying"
            )
        return {
            "provisioned": True,
            "key_id": key_id,
            "successor_envelope_sha256": hashlib.sha256(raw).hexdigest(),
            **{
                key: result[key]
                for key in ("site_id", "record_sha256", "operation", "verified")
                if key in result and isinstance(result[key], (str, bool))
            },
        }
    if args.command == "verify":
        material = recovery_material(packet)
        return {
            "authenticated": True,
            "envelope_sha256": hashlib.sha256(raw).hexdigest(),
            "machine_id": material["machine_id"],
            "host_identity_sha256": material["host_identity_sha256"],
            "ca_keys_match": True,
            "packet_schema": packet["schema"],
        }
    if args.command == "successor":
        recipient = args.recipient_public.read_bytes() if args.recipient_public else custody.public_der()
        encrypted, receipt = prepare_successor(
            raw, custody, recipient_der=recipient, expected=_expected(args), deployment_id=args.deployment_id
        )
        if public_pin(recipient) != public_pin(custody.public_der()):
            raise CustodyError("This command requires a recipient whose custody can verify the new packet")
        successor = decrypt_packet(
            encrypted,
            custody,
            expected={
                "machine_id": args.machine_id,
                "host_identity_sha256": args.host_identity_sha256,
                "stage": "static-seal-successor-pre-migration",
            },
        )
        recovery_material(successor)
        key = decode(successor["static_seal_key_b64"], 32, length=32)
        if hashlib.sha256(key).hexdigest() != receipt["key_id"]:
            raise CustodyError("Successor static key verification failed")
        write_new_private(args.output, encrypted)
        if private_read(args.output, MAX_PACKET) != encrypted:
            raise CustodyError("Successor durable reread failed")
        receipt.update({"offhost_durable": True, "decryption_verified": True})
        write_new_private(args.receipt, canonical(receipt) + b"\n")
        return receipt
    if args.command in ("unseal", "snapshot", "kms-provision"):
        payload = {"packet": packet, **_expected(args)}
        payload.pop("stage", None)
        if args.command == "kms-provision":
            payload["options"] = {"apply": args.apply, "expected_plan_sha256": args.plan_sha256}
            return parse_json(_ssh(args, "receive-kms-provision", payload))
        if args.command == "unseal":
            return parse_json(_ssh(args, "receive-unseal", payload))
        snapshot = _ssh(args, "receive-snapshot", payload, maximum=8 * 1024 * 1024)
        metadata = inspect_packet(raw)["aad"]
        metadata.update({"stage": "raft-snapshot-backup", "recorded_at": datetime.now(UTC).isoformat()})
        encrypted = encrypt_packet(
            {
                "schema": "pap-raft-snapshot-backup-v1",
                "snapshot_b64": base64.b64encode(snapshot).decode(),
                "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
                "recovery_envelope_sha256": hashlib.sha256(raw).hexdigest(),
            },
            custody.public_der(),
            metadata,
        )
        write_new_private(args.output, encrypted)
        return {
            "encrypted_backup": str(args.output),
            "envelope_sha256": hashlib.sha256(encrypted).hexdigest(),
            "snapshot_bytes": len(snapshot),
            "authority_state_included": False,
        }
    raise CustodyError("Unsupported operator command")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="pap-operator", description="Public workload setup and env-free operator custody, backup and recovery"
    )
    commands = root.add_subparsers(dest="command", required=True)
    workload = commands.add_parser("workload-init", help="Create a public workload configuration and registration")
    workload.add_argument("--adapter", choices=("netlify", "https-origin"), required=True)
    workload.add_argument("--issuer", required=True, help="Existing authority HTTPS origin")
    workload.add_argument("--audience", required=True, help="Existing authority audience")
    workload.add_argument("--origin", required=True, help="Dedicated workload HTTPS origin")
    workload.add_argument("--tenant", required=True)
    workload.add_argument("--output-directory", type=Path, required=True, help="New directory; never overwritten")
    workload.add_argument("--workload-id", help="Actual Netlify site UUID; generated for HTTPS origins if omitted")
    workload.add_argument("--grant-days", type=int, default=7, help="Absolute grant expiry in 1-30 days; default 7")
    workload.add_argument("--resource-path", default="/api/pap/records")
    workload.add_argument("--resource-action", default="records.read")
    workload.add_argument("--trust-origin", action="store_true", help="Acknowledge all origin administrators as trusted")
    workload.add_argument("--enable", action="store_true", help="Enable public config; requires --trust-origin")
    check = commands.add_parser("workload-check", help="Check public workload bindings offline without changing files")
    check.add_argument("--config", type=Path, required=True)
    check.add_argument("--registration", type=Path, required=True)
    check.add_argument("--authority-config", type=Path, help="Local authority configuration to check its public bindings")
    check.add_argument("--require-ready", action="store_true", help="Fail unless enabled, trusted and exactly registered")
    create = commands.add_parser("custody-create", help="Create a new operator custody identity")
    create.add_argument("--backend", choices=("keychain", "encrypted-pem"), required=True)
    create.add_argument("--directory", type=Path, required=True)
    create.add_argument("--application-tag")
    create.add_argument("--passphrase-fd", type=int)
    inspect = commands.add_parser("inspect", help="Inspect unauthenticated public envelope metadata")
    inspect.add_argument("--packet", type=Path, required=True)

    def custody_arguments(command):
        command.add_argument("--custody", type=Path, required=True, help="Owner-only custody metadata JSON")
        command.add_argument("--passphrase-fd", type=int)

    def recovery_arguments(command):
        custody_arguments(command)
        command.add_argument("--packet", type=Path, required=True)
        command.add_argument("--machine-id", required=True)
        command.add_argument("--host-identity-sha256", required=True)
        command.add_argument("--envelope-sha256", required=True)
        command.add_argument("--stage")

    def ssh_arguments(command, *, required=True):
        command.add_argument("--target", required=required)
        command.add_argument("--ssh-port", type=int, default=22)
        command.add_argument("--known-hosts", type=Path)
        command.add_argument("--remote-executable", default="/opt/pap/venv/bin/pap-operator")

    custody_arguments(commands.add_parser("public", help="Export the public pin and RSA JWK"))
    verify = commands.add_parser("verify", help="Authenticate a recovery packet in RAM")
    recovery_arguments(verify)
    successor = commands.add_parser(
        "successor", help="Create and verify a separately encrypted static-seal successor"
    )
    recovery_arguments(successor)
    successor.add_argument("--deployment-id", required=True)
    successor.add_argument("--recipient-public", type=Path)
    successor.add_argument("--output", type=Path, required=True)
    successor.add_argument("--receipt", type=Path, required=True)
    custody_provision = commands.add_parser(
        "custody-provision",
        help="Provision a separately deployed Netlify seal-custody record from encrypted operator custody",
    )
    recovery_arguments(custody_provision)
    custody_provision.add_argument("--config", type=Path, required=True)
    custody_provision.add_argument("--helper", type=Path, required=True)
    custody_provision.add_argument("--netlify-token-fd", type=int, required=True)
    credentials = commands.add_parser(
        "credential-import", help="Decrypt and import a credential directly into the broker"
    )
    custody_arguments(credentials)
    credentials.add_argument("--provider", choices=("openai", "nasa", "nlr"), required=True)
    inputs = credentials.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--encrypted-openai-backup", type=Path)
    inputs.add_argument("--secret-fd", type=int)
    credentials.add_argument("--name")
    credentials.add_argument("--organization-id")
    credentials.add_argument("--project-id")
    credentials.add_argument("--socket", type=Path, default=Path("/run/pap-admin/admin.sock"))
    credentials.add_argument("--admin-user", default="pap-admin")
    credentials.add_argument("--issuer-user", default="pap-issuer")
    ssh_arguments(credentials, required=False)
    revoke = commands.add_parser(
        "credential-revoke", help="Revoke central provider access without distributing its key"
    )
    revoke.add_argument("--provider", choices=("openai", "nasa", "nlr"), required=True)
    revoke.add_argument("--socket", type=Path, default=Path("/run/pap-admin/admin.sock"))
    revoke.add_argument("--admin-user", default="pap-admin")
    revoke.add_argument("--issuer-user", default="pap-issuer")
    ssh_arguments(revoke, required=False)
    for name in ("unseal", "snapshot", "kms-provision"):
        command = commands.add_parser(
            name,
            help={
                "unseal": "Historical Shamir unseal",
                "snapshot": "Encrypt a Raft snapshot in operator custody",
                "kms-provision": "Plan and provision least-privilege provider key custody",
            }[name],
        )
        recovery_arguments(command)
        ssh_arguments(command)
        if name == "snapshot":
            command.add_argument("--output", type=Path, required=True)
        if name == "kms-provision":
            command.add_argument("--apply", action="store_true")
            command.add_argument("--plan-sha256")
    receive = commands.add_parser("receive-credential", help=argparse.SUPPRESS)
    receive.add_argument("--socket", type=Path, default=Path("/run/pap-admin/admin.sock"))
    receive.add_argument("--admin-user", default="pap-admin")
    receive.add_argument("--issuer-user", default="pap-issuer")
    commands.add_parser("receive-unseal", help=argparse.SUPPRESS)
    commands.add_parser("receive-snapshot", help=argparse.SUPPRESS)
    commands.add_parser("receive-kms-provision", help=argparse.SUPPRESS)
    return root


def main(argv=None) -> int:
    try:
        harden_process()
        args = parser().parse_args(argv)
        result = execute(args)
        if result is not None:
            print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False))
        if args.command == "workload-check" and result is not None and result.get("ok") is False:
            return 2
        return 0
    except WorkloadSetupError as exc:
        print(json.dumps({
            "ok": False, "ready": False, "scope": "public_workload_bindings",
            "deployment_accepted": False,
            "findings": [{"code": exc.code, "field": exc.field, "severity": "error"}],
        }), file=sys.stderr)
        return 2
    except CustodyError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        # Avoid library exceptions containing sensitive JSON or paths passed
        # through remote APIs. Callers get only a stable failure category.
        print(
            '{"ok":false,"error":"Operator action failed; inspect protected state before retrying"}',
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
