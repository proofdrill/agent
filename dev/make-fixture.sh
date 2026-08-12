#!/usr/bin/env bash
# Writes one realistic artefact to $1 — and, if $2 is given, the cluster globals
# beside it — then destroys the cluster that produced them, because a drill
# restores into a cluster that never held the original and a fixture made any
# other way would not exercise that.
#
#   docker run --rm -v fixtures:/out --entrypoint /usr/local/bin/make-fixture.sh \
#     proofdrill-agent:verify /out/db-2026-08-11.dump /out/globals-2026-08-11.sql
set -euo pipefail

DESTINATION="${1:?usage: make-fixture.sh <destination.dump> [globals.sql]}"
GLOBALS="${2:-}"

# Which major writes the fixture, overridable because the image carries several.
#
# A drill picks its binaries from what the ARTEFACT says wrote it, never from
# what is newest. The only way to prove that is to hand it an artefact written
# by something other than the newest thing installed — with the default, "it
# chose correctly" and "it chose the last one" are the same observation, and a
# regression that made the agent always reach for the newest major would pass
# every check here.
PG_MAJOR="${PG_MAJOR:-$(ls /usr/lib/postgresql | sort -n | tail -1)}"
test -x "/usr/lib/postgresql/${PG_MAJOR}/bin/initdb" \
  || { echo "this image does not carry PostgreSQL ${PG_MAJOR}" >&2; exit 1; }
export PATH="/usr/lib/postgresql/${PG_MAJOR}/bin:${PATH}"

DATA=/tmp/fixture/pgdata
SOCK=/tmp/fixture/sock
mkdir -p "$SOCK" "$(dirname "$DESTINATION")"

initdb -D "$DATA" --username=source --auth=trust --encoding=UTF8 --locale=C --no-sync >/dev/null
pg_ctl -D "$DATA" -o "-k $SOCK -h ''" -w -l /tmp/fixture.log start >/dev/null
export PGHOST="$SOCK" PGUSER=source

psql -q -v ON_ERROR_STOP=1 -d postgres -c 'CREATE ROLE app_role NOLOGIN'
psql -q -v ON_ERROR_STOP=1 -d postgres -c 'CREATE DATABASE production'
psql -q -v ON_ERROR_STOP=1 -d production <<'SQL'
CREATE TABLE tenant_rows (
  id        bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL,
  payload   text NOT NULL
);
INSERT INTO tenant_rows (tenant_id, payload)
SELECT gen_random_uuid(), repeat('x', 200) FROM generate_series(1, 20000);
ALTER TABLE tenant_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_rows FORCE ROW LEVEL SECURITY;
-- Named, rather than left to PUBLIC: a tenant isolation policy is written about
-- the role the application connects as, and naming it is what lets a drill ask
-- whether that role is exempt from it.
CREATE POLICY tenant_isolation ON tenant_rows TO app_role
  USING (tenant_id::text = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT ON tenant_rows TO app_role;
SQL

pg_dump -Fc -d production -f "$DESTINATION"

# The second artefact, and it comes from the same cluster at the same moment —
# which is the pair a customer is asked to write beside each other nightly.
if [ -n "$GLOBALS" ]; then
  mkdir -p "$(dirname "$GLOBALS")"
  pg_dumpall --globals-only --no-role-passwords > "$GLOBALS"
fi

pg_ctl -D "$DATA" -m immediate stop >/dev/null 2>&1
rm -rf /tmp/fixture

printf 'wrote %s (%s)\n' "$DESTINATION" "$(du -h "$DESTINATION" | cut -f1)"
[ -n "$GLOBALS" ] && printf 'wrote %s (%s)\n' "$GLOBALS" "$(du -h "$GLOBALS" | cut -f1)"
exit 0
