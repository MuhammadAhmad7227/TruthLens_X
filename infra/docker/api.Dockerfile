# TruthLens X — API image
#
# Referenced by infra/compose/docker-compose.yml. This file did not exist when that compose file was
# written, so `docker compose build` failed before it could run; it is added here as part of the M1
# foundation.
#
# IMAGE PINNING — HONEST STATE, ACTION REQUIRED BEFORE PRODUCTION
#   DEPLOYMENT_GUIDE's image table requires every image to be pinned **by digest**. The base image
#   below is pinned by tag only, because resolving a digest requires querying a container registry
#   and no registry was reachable from the environment where this was written. Inventing a digest
#   would be worse than leaving a tag: a fabricated sha256 cannot be pulled and would look like a
#   real pin. On a networked host run:
#       docker buildx imagetools inspect python:3.11-slim
#   and replace the tag with the digest before any production deployment.
#
# The container binds 0.0.0.0 (required for the compose network to reach it) and publishes **no**
# host port: per DEPLOYMENT_GUIDE's port-exposure rule, only nginx publishes 80/443.

FROM python:3.11-slim AS base

# Fail loudly, no .pyc litter, unbuffered so structlog output reaches `docker logs` immediately.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# libmagic is the file-type backend (BSD-2-style licence, THIRD_PARTY_LICENSE_AUDIT §4.3).
# No poppler, no ClamAV, no CUDA here: those are opt-in extras behind ENABLE_* flags and belong in
# dedicated images, so the default image stays permissive-licensed (ADR-0001).
RUN apt-get update \
    && apt-get install --no-install-recommends -y libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/truthlens

# Dependencies and source are installed in ONE layer, deliberately.
#
# The usual "copy pyproject first, install deps, copy source later" cache trick is wrong here:
# hatchling builds the wheel from `packages = ["app"]`, so it fails without the source present, and a
# non-editable install copies `app/` into site-packages — a later COPY of backend/app would leave the
# image running the stale site-packages copy. Correctness over cache hits.
COPY backend/ ./backend/
RUN pip install --upgrade pip \
    && pip install "./backend[db]"

# Fixed non-root UID (DEPLOYMENT_GUIDE: "every image runs as a fixed non-root UID"). The evidence
# volume is mounted separately and must be owned by this UID on the host.
RUN groupadd --gid 10001 tlx \
    && useradd --uid 10001 --gid tlx --shell /usr/sbin/nologin --create-home tlx
USER 10001

EXPOSE 8000

# Only the reverse proxy on the compose network may supply forwarded headers. Trusting "*" would let
# any client set X-Forwarded-For and write a spoofed source address into the audit log — which for a
# forensic platform is evidence tampering, not a convenience. The value must match the subnet that
# docker-compose.yml assigns to the `tlxnet` network.
ENV FORWARDED_ALLOW_IPS="172.28.0.0/24"

# --factory is REQUIRED: app/main.py deliberately has no module-level `app` object, so importing the
# module never validates configuration as a side effect. Configuration is validated when the server
# starts, and startup is fail-closed. No --reload: this is a runtime image.
CMD ["sh", "-c", "exec uvicorn app.main:create_app --factory \
     --host 0.0.0.0 --port 8000 \
     --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS}\""]
