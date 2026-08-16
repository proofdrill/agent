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

# EVERY MAJOR STILL SUPPORTED UPSTREAM, IN ONE IMAGE, AND ON PURPOSE.
#
# pg_restore must match the major that wrote the archive — restoring across
# majors is not a restore, and PostgresBinaries.For() returns null rather than
# reaching for the nearest one. So an image carrying a single major serves only
# the customers who happen to run it, and answers every other one with a
# correction. A backup verification product that cannot verify your backup
# because of our packaging is not a product.
#
# The alternative was a tag per major — agent:1-pg16 — and it is rejected for
# the reason the whole onboarding is built on: step 4 is ONE paste. A customer
# who has to know which major wrote their nightly dump before they can choose an
# image is a customer answering, at install time, the question they installed
# this to have answered. The agent reads it out of the artefact instead.
#
# The list is upstream's supported set. A major that upstream has stopped
# patching is one we would be carrying into other people's infrastructure long
# after its last security fix, and the refusal an unsupported major gets names
# what is here — which is a better answer than a stale binary.
ARG PG_MAJORS="14 15 16 17 18"

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    . /etc/os-release; \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    packages=""; \
    for major in ${PG_MAJORS}; do packages="${packages} postgresql-${major}"; done; \
    # Unquoted on purpose: the list is several package names, not one.
    # shellcheck disable=SC2086
    apt-get install -y --no-install-recommends ${packages}; \
    apt-get purge -y --auto-remove curl gnupg; \
    rm -rf /var/lib/apt/lists/*; \
    # Asserted here rather than discovered by a customer whose drill returns a
    # correction. PGDG does not necessarily build every major for every Debian
    # release, and `apt-get install` of a package that does not exist fails
    # loudly — but a major that resolves to an EMPTY bin directory would not,
    # and AvailableMajors() would simply not list it. The image says what it
    # carries, at build time, or it does not build.
    for major in ${PG_MAJORS}; do \
      test -x "/usr/lib/postgresql/${major}/bin/initdb" \
        || { echo "PostgreSQL ${major} has no initdb: this image would silently not carry it" >&2; exit 1; }; \
    done

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

# This image says, in the image, that it is one.
#
# The agent reports a hostname, and inside a container `Environment.MachineName`
# is the CONTAINER ID unless somebody passed --hostname. That value looks like
# the one field identifying which machine to go and restart, and it is the one
# field that does not survive `docker run`: recreate the container and the same
# physical box reports a different name. So the agent has to know when its own
# machine name is worthless and say so.
#
# Declared here rather than sniffed at runtime — no /.dockerenv, no reading
# /proc/1/cgroup. Those are guesses about somebody else's runtime that are wrong
# on Podman, on Kubernetes and on whatever is next; this is true by construction,
# because we are the ones who build the image. A copy of the binary running
# outside a container never sees it, which is exactly right.
ENV PROOFDRILL_IN_CONTAINER=1

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
# openssl is here and NOT in the product image: it is the independent judge of
# our signatures. Checking a signature with the code that produced it proves
# only that the code agrees with itself.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY dev/verify.sh dev/make-fixture.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/verify.sh /usr/local/bin/make-fixture.sh
USER drill
ENTRYPOINT ["/usr/local/bin/verify.sh"]
