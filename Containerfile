# OpenPath-AI container image.
#
# OpenPath is a STATELESS BATCH CLI: it collects evidence, answers, and exits. It
# keeps no state between runs, opens no listening port, and needs no network. The
# image reflects that -- a minimal, read-only-friendly, non-root batch tool. See
# docs/DEPLOYMENT.md for the full deployment doctrine (start/discover/persist/
# recover/upgrade/permission/health/readiness/restart/reboot/rotation/disk-full).
#
# Build:   docker build -f Containerfile -t openpath-ai:0.1.0 .
# Health:  docker run --rm openpath-ai:0.1.0 --selfcheck
# Analyze a live host (read-only mount; grant read of root-only logs via the
# capability rather than running privileged):
#   docker run --rm --read-only --tmpfs /tmp \
#     --cap-add DAC_READ_SEARCH -v /:/host:ro \
#     openpath-ai:0.1.0 --data-root /host --coverage
# Analyze an offline evidence bundle:
#   docker run --rm --read-only --tmpfs /tmp -v "$PWD/bundle:/evidence:ro" \
#     openpath-ai:0.1.0 --data-root /evidence --all-users -w "last 24 hours"

FROM python:3.12-slim AS base

# Zero third-party runtime dependencies (pure stdlib), so there is nothing to
# pip-install and no wheels to fetch at build time -- the copy IS the install.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/openpath
COPY openpath/ ./openpath/
COPY pyproject.toml README.md ./

# Install the console entrypoint (no deps resolved -> no network needed).
RUN pip install --no-cache-dir --no-deps . \
    && python -m openpath --selfcheck   # fail the build if the wiring is broken

# Run unprivileged by default. Reading root-only host logs (audit.log, btmp,
# shadow) then requires an explicit --cap-add DAC_READ_SEARCH at run time; without
# it OpenPath discloses those sources as UNREADABLE (never a false "nothing
# happened"), so a non-root run is safe, just narrower.
RUN useradd --system --no-create-home --uid 65532 openpath
USER 65532

# OCI metadata.
LABEL org.opencontainers.image.title="OpenPath-AI" \
      org.opencontainers.image.description="Evidence-first forensic Q&A over Linux user activity (stateless batch CLI)." \
      org.opencontainers.image.source="https://github.com/openpathdev2026/OpenPath-AI"

# Liveness/health: the self-check is host-independent, needs no privilege and no
# network, and exits non-zero if the build is mis-wired.
HEALTHCHECK --interval=1h --timeout=30s --retries=1 \
    CMD ["python", "-m", "openpath", "--selfcheck"]

ENTRYPOINT ["python", "-m", "openpath"]
CMD ["--selfcheck"]
