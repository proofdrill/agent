# Spike 0 — is docs/03 §10.2 option B real?
#
# ONE question, and nothing else: can an UNPRIVILEGED process inside a container
# start its own PostgreSQL as a child process and restore a dump into it, with
# no Docker socket, no host root and no listening port?
#
# It is not a preference being explored. README.md already promises it in public
# — "It needs no privileged access — no Docker socket, no host root" — so this
# is a published claim being checked before any code is written on top of it.
#
# This directory is a spike. When the answer is recorded in the repository it
# gets deleted or promoted; it is not a base image and nothing should extend it.

# Same digest the control plane pins for its runtime images, so the spike
# measures the base the agent will actually be built on. Pinned by digest
# because a tag is a moving target and a spike whose base moved is not evidence.
FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:68d35011fe04a39cca38208d392ed48f2df15653633dca16dbc4582d07342b9f

ARG PG_MAJOR=17

# PGDG rather than Debian's own postgresql package. Debian ships one major; the
# agent will eventually need several side by side, so installing from the
# repository that matrix has to come from is what makes the size measured here
# mean something.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    . /etc/os-release; \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-${PG_MAJOR}"; \
    apt-get purge -y --auto-remove curl gnupg; \
    rm -rf /var/lib/apt/lists/*

# PGDG does not put the binaries on PATH — every major lives in its own
# directory, which is precisely what makes several of them installable at once.
ENV PATH="/usr/lib/postgresql/${PG_MAJOR}/bin:${PATH}"

# The constraint is self-enforcing rather than a policy: postgres refuses to
# start as root, so an image that runs its own server cannot also be running as
# root. That is the argument, and it is nice that the software makes it for us.
RUN set -eux; \
    useradd --system --uid 10001 --create-home --home-dir /home/drill drill; \
    mkdir -p /work; \
    chown drill:drill /work

COPY spike.sh /usr/local/bin/spike.sh
RUN chmod 0755 /usr/local/bin/spike.sh

USER drill
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/spike.sh"]
