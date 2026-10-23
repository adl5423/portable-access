"""Build and verify isolated containers with an ephemeral local Caddy certificate.

This is a Docker acceptance command, separate from the protocol pytest suite.
It creates only uniquely named pap-portability-* containers and volumes, then
removes those resources. It never requests a public ACME certificate.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "examples" / "docker-https"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--project", default="pap-portability-" + uuid.uuid4().hex[:12])
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"pap-portability-[a-z0-9-]{1,48}", args.project):
        parser.error("project name must start with pap-portability- and contain lowercase letters, digits or hyphens")
    env = {**os.environ, "PAP_HOSTNAME": "workload.example.com"}
    compose = ["compose", "-p", args.project, "-f", str(EXAMPLE / "compose.yaml")]
    gateway_name = args.project + "-tls-check"

    def docker(*arguments, timeout=180, check=True):
        result = subprocess.run([args.docker, *arguments], cwd=ROOT, env=env, capture_output=True,
                                text=True, timeout=timeout, check=False)
        if check and result.returncode:
            raise RuntimeError(f"Docker command failed ({arguments[0]}): {result.stderr[-4000:]}")
        return result.stdout.strip()

    def inspect(identifier):
        return json.loads(docker("inspect", identifier))[0]

    def verify_isolation(identifier):
        description = inspect(identifier)
        host = description["HostConfig"]
        assert description["Config"]["User"] == "10001:10001"
        assert host["ReadonlyRootfs"] is True
        assert "ALL" in host["CapDrop"] and not host["CapAdd"]
        assert "no-new-privileges:true" in host["SecurityOpt"]
        assert 0 < host["Memory"] <= 256 * 1024 * 1024
        assert host["PidsLimit"] == 64
        assert 0 < host["NanoCpus"] <= 1_000_000_000
        return description

    def https_get(port, context, path):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname="workload.example.com") as connection:
                connection.sendall((f"GET {path} HTTP/1.1\r\nHost: workload.example.com\r\n"
                                    "Connection: close\r\n\r\n").encode("ascii"))
                response = http.client.HTTPResponse(connection)
                response.begin()
                return response.status, response.read(4097)

    try:
        docker(*compose, "config", "--quiet")
        if not args.skip_build:
            docker(*compose, "build", "--quiet", "app", "gateway", timeout=1200)
        docker(*compose, "up", "-d", "--wait", "--wait-timeout", "60", "app", timeout=90)
        app_id = docker(*compose, "ps", "-q", "app")
        app = verify_isolation(app_id)
        assert app["State"]["Health"]["Status"] == "healthy"
        assert all(not mapping for mapping in app["NetworkSettings"]["Ports"].values())
        application_check = """
import json, os, pathlib, stat, urllib.error, urllib.request
assert os.getuid() == 10001
assert 'CapEff:\\t0000000000000000' in pathlib.Path('/proc/self/status').read_text()
assert json.load(urllib.request.urlopen('http://127.0.0.1:8080/health/live')) == {'alive': True}
for path, expected in [('/health/ready',503),('/api/pap/records',503),('/check',404)]:
    try: urllib.request.urlopen('http://127.0.0.1:8080'+path)
    except urllib.error.HTTPError as error: assert error.code == expected
    else: raise AssertionError('unprotected route')
info = pathlib.Path('/run/pap-workload/control.sock').stat()
assert stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == 10001
try: pathlib.Path('/must-be-read-only').write_text('forbidden')
except OSError: pass
else: raise AssertionError('writable root filesystem')
pathlib.Path('/tmp/bounded-test').write_text('temporary')
print('application isolation verified')
"""
        docker("exec", app_id, "python", "-c", application_check)
        # Validate the production config as the real unprivileged gateway UID.
        docker(*compose, "run", "--rm", "--no-deps", "gateway", "caddy", "validate",
               "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
        with tempfile.TemporaryDirectory(prefix="pap-portability-caddy-") as directory:
            fixture = Path(directory) / "Caddyfile"
            production = (EXAMPLE / "Caddyfile").read_text()
            marker = "\n{$PAP_HOSTNAME:workload.example.com} {\n"
            assert production.count(marker) == 1
            fixture.write_text(production.replace(marker, marker + "\ttls internal\n"))
            fixture.chmod(0o644)
            docker(*compose, "run", "-d", "--no-deps", "--name", gateway_name,
                   "--publish", "127.0.0.1::8443", "--publish", "127.0.0.1::8080",
                   "--volume", f"{fixture}:/etc/caddy/Caddyfile:ro", "gateway")
            gateway = verify_isolation(gateway_name)
            assert gateway["State"]["Running"] is True
            assert docker("exec", gateway_name, "stat", "-c", "%u:%g:%a", "/data") == "10001:10001:700"
            assert docker("exec", gateway_name, "getcap", "/usr/bin/caddy") == ""
            public_ca = ""
            for _ in range(80):
                public_ca = docker("exec", gateway_name, "cat", "/data/caddy/pki/authorities/local/root.crt", check=False)
                if "BEGIN CERTIFICATE" in public_ca:
                    break
                time.sleep(0.25)
            assert public_ca
            context = ssl.create_default_context(cadata=public_ca)
            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            bindings = inspect(gateway_name)["NetworkSettings"]["Ports"]
            https_port = int(bindings["8443/tcp"][0]["HostPort"])
            http_port = int(bindings["8080/tcp"][0]["HostPort"])
            for attempt in range(20):
                try:
                    status, body = https_get(https_port, context, "/health/live")
                    assert status == 200 and json.loads(body) == {"alive": True}
                    break
                except (OSError, AssertionError):
                    if attempt == 19:
                        raise
                    time.sleep(0.25)
            status, body = https_get(https_port, context, "/health/ready")
            assert status == 503 and json.loads(body) == {"ready": False}
            redirect = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
            try:
                redirect.request("GET", "/health/live", headers={"Host": "workload.example.com"})
                response = redirect.getresponse()
                assert response.status == 308
                assert response.getheader("Location") == "https://workload.example.com/health/live"
                response.read()
            finally:
                redirect.close()
            print(json.dumps({"container_acceptance": "passed", "non_root": True, "read_only": True,
                              "capabilities_dropped": True, "fresh_volume_owner": 10001,
                              "tls_verified": True, "public_app_port": False, "disabled_readiness": 503}))
        return 0
    finally:
        docker("rm", "-f", gateway_name, check=False)
        docker(*compose, "down", "--volumes", "--remove-orphans", timeout=60, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
