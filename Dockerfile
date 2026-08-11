# The Proofdrill agent.
#
# It carries PostgreSQL server binaries and starts its own cluster as a child
# process, so it needs no Docker socket and no root on the host. Spike 0
# measured that arrangement before this file existed: 45 MB per major, initdb in
# 3.5 s, and no TCP listener at all. `spike/FINDINGS.md`.

# Digests, not tags. A tag is a moving target, and an image whose base moved is
# not the image that was tested.
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS build

WORKDIR /src

# The lock file is copied BESIDE its project and before the restore, because
# `--locked-mode` requires it to be there already. Copying only the .csproj
# produces a restore that fails with a message about the lock file being absent,
# which reads as "delete the lock file" and is the opposite of the fix.
COPY Directory.Build.props ./
COPY src/Proofdrill.Agent/Proofdrill.Agent.csproj src/Proofdrill.Agent/
COPY src/Proofdrill.Agent/packages.lock.json src/Proofdrill.Agent/
RUN dotnet restore src/Proofdrill.Agent/Proofdrill.Agent.csproj --locked-mode

COPY src/ src/
ARG SOURCE_VERSION=0.0.0-dev
# SOURCE_VERSION and never VERSION: MSBuild reads environment variables as
# case-insensitive global properties, so `--build-arg VERSION=` silently becomes
# $(Version) for every project in the build.
RUN dotnet publish src/Proofdrill.Agent/Proofdrill.Agent.csproj \
      --configuration Release --no-restore --output /app \
      -p:Version="${SOURCE_VERSION}"

FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:68d35011fe04a39cca38208d392ed48f2df15653633dca16dbc4582d07342b9f AS agent

ARG PG_MAJOR=17

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

# postgres refuses to run as root, which makes "no privileged access" enforced by
# the software rather than promised by us.
RUN set -eux; \
    useradd --system --uid 10001 --create-home --home-dir /home/drill drill; \
    mkdir -p /work; \
    chown drill:drill /work

COPY --from=build /app /opt/proofdrill
RUN ln -s /opt/proofdrill/proofdrill /usr/local/bin/proofdrill

USER drill
WORKDIR /work

# The subcommand is what the customer types after the image name, exactly as the
# installation page shows it: `docker run … ghcr.io/proofdrill/agent:1 drill …`.
ENTRYPOINT ["/usr/local/bin/proofdrill"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# Verification only. Built with `--target verify`, never published: it carries a
# script that manufactures a fixture, and a product image should contain nothing
# that exists for our benefit rather than the customer's.
# ---------------------------------------------------------------------------
FROM agent AS verify
USER root
COPY dev/verify.sh dev/make-fixture.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/verify.sh /usr/local/bin/make-fixture.sh
USER drill
ENTRYPOINT ["/usr/local/bin/verify.sh"]
