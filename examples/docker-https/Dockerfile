# Digests are the official multi-platform image indexes verified on 2026-10-23.
FROM python:3.14.7-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56 AS builder
WORKDIR /build
COPY pyproject.toml requirements.lock requirements-dev.lock LICENSE NOTICE ./
COPY pap ./pap
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements-dev.lock \
    && python -m pip download --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock -d /wheels \
    && python -m pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.14.7-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 pap && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent pap \
    && install -d -o 10001 -g 10001 -m 0700 /run/pap-workload
COPY --from=builder /wheels /wheels
COPY --from=builder /build/requirements.lock /wheels/requirements.lock
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels --require-hashes -r /wheels/requirements.lock \
    && python -m pip install --no-cache-dir --no-index --no-deps /wheels/portable_access_reference-*.whl \
    && rm -rf /wheels
WORKDIR /opt/pap-example
COPY --chown=10001:10001 examples/docker-https/app.py ./app.py
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python", "/opt/pap-example/app.py"]
