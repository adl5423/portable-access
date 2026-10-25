# Build a test toolchain without copying or executing project source.
FROM python:3.14.7-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56
COPY requirements-dev.lock /tools/requirements-dev.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r /tools/requirements-dev.lock
WORKDIR /src
ENTRYPOINT ["python", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp=/scratch/t"]
