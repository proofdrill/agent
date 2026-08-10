#!/usr/bin/env bash
# Spike 0. Prints numbers and exit codes, never opinions.
#
# Two clusters, on purpose. Cluster A stands in for the customer's production
# database and is DESTROYED before anything is restored; cluster B is the
# throwaway the agent creates. Restoring into the cluster that produced the dump
# would prove nothing about roles, because roles are cluster-wide and would
# still be sitting there.
set -uo pipefail

A_DATA=/work/a/pgdata; A_SOCK=/work/a/sock
B_DATA=/work/b/pgdata; B_SOCK=/work/b/sock
DUMP=/work/source.dump

say()  { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
ms()   { date +%s%3N; }
fail() { printf '\nSPIKE FAILED: %s\n' "$1"; exit 1; }

cleanup() {
  pg_ctl -D "$A_DATA" -m immediate stop >/dev/null 2>&1
  pg_ctl -D "$B_DATA" -m immediate stop >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
say "question 1 — is this an unprivileged process?"
# ---------------------------------------------------------------------------
id
[ "$(id -u)" -ne 0 ] || fail "running as root, so the spike would prove nothing"
echo "postgres version: $(postgres --version)"

# ---------------------------------------------------------------------------
say "cluster A — standing in for the customer's production database"
# ---------------------------------------------------------------------------
mkdir -p "$A_SOCK" "$B_SOCK"
t0=$(ms)
initdb -D "$A_DATA" --username=drill --auth=trust --encoding=UTF8 --locale=C >/dev/null \
  || fail "initdb refused to create a cluster"
t1=$(ms)
echo "initdb: $((t1 - t0)) ms"

# -h '' is the load-bearing argument: no TCP listener of any kind, so nothing
# this container starts is reachable from the host or from anywhere else.
pg_ctl -D "$A_DATA" -o "-k $A_SOCK -h ''" -w -l /work/a.log start >/dev/null \
  || { cat /work/a.log; fail "postgres would not start as an unprivileged child process"; }
echo "postgres started, pid $(head -1 "$A_DATA/postmaster.pid")"

export PGHOST="$A_SOCK"
createdb source || fail "createdb failed"

psql -q -v ON_ERROR_STOP=1 -d source <<'SQL' || fail "could not build the source database"
CREATE ROLE app_role NOLOGIN;
CREATE TABLE tenant_rows (
  id        bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL,
  payload   text NOT NULL
);
INSERT INTO tenant_rows (tenant_id, payload)
SELECT gen_random_uuid(), repeat('x', 200) FROM generate_series(1, 50000);
ALTER TABLE tenant_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_rows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_rows
  USING (tenant_id::text = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT ON tenant_rows TO app_role;
SQL

echo "rows in source:      $(psql -qtAc 'SELECT count(*) FROM tenant_rows' -d source)"
echo "rls enabled/forced:  $(psql -qtAc "SELECT relrowsecurity||'/'||relforcerowsecurity FROM pg_class WHERE relname='tenant_rows'" -d source)"
echo "policies:            $(psql -qtAc "SELECT count(*) FROM pg_policies WHERE tablename='tenant_rows'" -d source)"

# ---------------------------------------------------------------------------
say "question 2 — no TCP listener at all"
# ---------------------------------------------------------------------------
if psql -h 127.0.0.1 -p 5432 -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
  fail "something is listening on TCP 5432 — the no-inbound-port claim is false"
fi
echo "TCP 127.0.0.1:5432 refuses connections, as -h '' intends"

# ---------------------------------------------------------------------------
say "the artefact"
# ---------------------------------------------------------------------------
t0=$(ms)
pg_dump -Fc -d source -f "$DUMP" || fail "pg_dump failed"
t1=$(ms)
echo "pg_dump: $((t1 - t0)) ms, $(du -h "$DUMP" | cut -f1)"

# The original is now gone, exactly as it is for a real drill: the agent has an
# artefact and no access to the database that produced it.
pg_ctl -D "$A_DATA" -m immediate stop >/dev/null 2>&1
rm -rf /work/a
echo "cluster A destroyed — only the artefact survives"

# ---------------------------------------------------------------------------
say "cluster B — the throwaway the agent creates"
# ---------------------------------------------------------------------------
initdb -D "$B_DATA" --username=drill --auth=trust --encoding=UTF8 --locale=C >/dev/null \
  || fail "initdb refused to create the second cluster"
pg_ctl -D "$B_DATA" -o "-k $B_SOCK -h ''" -w -l /work/b.log start >/dev/null \
  || { cat /work/b.log; fail "the throwaway cluster would not start"; }
export PGHOST="$B_SOCK"
createdb restored || fail "createdb on the throwaway failed"

t0=$(ms)
pg_restore -d restored "$DUMP" 2>/work/restore.err
RESTORE_EXIT=$?
t1=$(ms)
echo "pg_restore exit code: $RESTORE_EXIT   (measured RTO for this artefact: $((t1 - t0)) ms)"
if [ -s /work/restore.err ]; then
  echo "--- pg_restore wrote to stderr ---"
  cat /work/restore.err
  echo "----------------------------------"
fi

# ---------------------------------------------------------------------------
say "question 3 — did the guarantees survive the round trip?"
# ---------------------------------------------------------------------------
echo "rows restored:       $(psql -qtAc 'SELECT count(*) FROM tenant_rows' -d restored)"
echo "rls enabled/forced:  $(psql -qtAc "SELECT relrowsecurity||'/'||relforcerowsecurity FROM pg_class WHERE relname='tenant_rows'" -d restored)"
echo "policies:            $(psql -qtAc "SELECT count(*) FROM pg_policies WHERE tablename='tenant_rows'" -d restored)"
echo "role app_role exists: $(psql -qtAc "SELECT count(*) FROM pg_roles WHERE rolname='app_role'" -d restored)"
echo "grants to app_role:   $(psql -qtAc "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee='app_role'" -d restored)"

# ---------------------------------------------------------------------------
say "the numbers that decide the image and the limits"
# ---------------------------------------------------------------------------
echo "artefact:            $(du -sh "$DUMP" | cut -f1)"
echo "restored data dir:   $(du -sh "$B_DATA" | cut -f1)"
echo "work total:          $(du -sh /work | cut -f1)"
echo "postgres binaries:   $(du -sh /usr/lib/postgresql | cut -f1)"

printf '\nSPIKE COMPLETE\n'
