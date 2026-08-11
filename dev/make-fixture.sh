#!/usr/bin/env bash
# Writes one realistic artefact to $1, then destroys the cluster that produced
# it — because a drill restores into a cluster that never held the original, and
# a fixture made any other way would not exercise that.
#
#   docker run --rm -v fixtures:/out --entrypoint /usr/local/bin/make-fixture.sh \
#     proofdrill-agent:verify /out/db-2026-08-11.dump
set -euo pipefail

DESTINATION="${1:?usage: make-fixture.sh <destination.dump>}"

PG_MAJOR="$(ls /usr/lib/postgresql | sort -n | tail -1)"
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
CREATE POLICY tenant_isolation ON tenant_rows
  USING (tenant_id::text = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT ON tenant_rows TO app_role;
SQL

pg_dump -Fc -d production -f "$DESTINATION"
pg_ctl -D "$DATA" -m immediate stop >/dev/null 2>&1
rm -rf /tmp/fixture

printf 'wrote %s (%s)\n' "$DESTINATION" "$(du -h "$DESTINATION" | cut -f1)"
