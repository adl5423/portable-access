#!/bin/sh
set -eu
task_source=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
task_builder=$(mktemp -d "${TMPDIR:-/tmp}/pap-buildx.XXXXXX")
trap 'rm -rf -- "$task_builder"' EXIT HUP INT TERM
BUILDX_CONFIG="$task_builder" docker build --file "$task_source/deploy/linux/Dockerfile.activation" --tag pap-runtime-activation-test:local "$task_source"
docker run --rm --read-only --network none \
  --tmpfs /tmp:rw,nosuid,noexec,size=64m --tmpfs /run:rw,nosuid,noexec,size=1m,mode=0755 \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add KILL \
  --security-opt no-new-privileges \
  pap-runtime-activation-test:local
