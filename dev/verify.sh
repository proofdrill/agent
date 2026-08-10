#!/usr/bin/env bash
# Verification for `proofdrill drill`, run inside the agent image.
#
#   docker build --target verify -t proofdrill-agent:verify .
#   docker run --rm --cap-drop=ALL --security-opt=no-new-privileges --memory=1g proofdrill-agent:verify
#
# It manufactures its own artefacts from a SOURCE cluster and then DESTROYS that
# cluster before drilling, because roles are cluster-wide: restoring into the
# cluster that produced the dump would prove nothing about them, and that is the
# whole finding of spike 0.
#
# Three artefacts, because a suite whose checks can only pass is decoration:
#
#   with-roles.dump    rows, forced RLS, a policy, a grant   -> drill PASSES level 1
#   without-roles.dump the same without the grant            -> drill PASSES level 1
#   empty-table.dump   a valid archive containing NO rows    -> drill FAILS
#
# The third is the product's founding failure: an archive that is well formed,
# restores with exit code 0, and carries nothing.
#
# NOT COVERED, and said here rather than discovered later: there is no test in
# which a level 3 comparison legitimately FAILS. Making one end to end needs a
# restore that loses a guarantee, and every way of manufacturing that is either
# contrived or closed by the agent itself. The comparison has been watched
# failing by hand — role ordering, before it was canonicalised — but that is not
# an assertion. Unit tests over SecurityDdl.Compare are where this belongs.
set -uo pipefail

PG_MAJOR="$(ls /usr/lib/postgresql | sort -n | tail -1)"
export PATH="/usr/lib/postgresql/${PG_MAJOR}/bin:${PATH}"

SRC_DATA=/work/source/pgdata
SRC_SOCK=/work/source/sock
FAILURES=0

say()  { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
note() { printf '     %s\n' "$1"; }

expect() {
  local what="$1" wanted="$2" got="$3"
  if [ "$wanted" = "$got" ]; then
    printf '  [pass] %s (exit %s)\n' "$what" "$got"
  else
    printf '  [FAIL] %s: expected exit %s, got %s\n' "$what" "$wanted" "$got"
    FAILURES=$((FAILURES + 1))
  fi
}

# ---------------------------------------------------------------------------
say "manufacturing the artefacts from a source cluster"
# ---------------------------------------------------------------------------
mkdir -p "$SRC_SOCK"
initdb -D "$SRC_DATA" --username=source --auth=trust --encoding=UTF8 --locale=C --no-sync >/dev/null
pg_ctl -D "$SRC_DATA" -o "-k $SRC_SOCK -h ''" -w -l /work/source.log start >/dev/null
export PGHOST="$SRC_SOCK" PGUSER=source

psql -q -v ON_ERROR_STOP=1 -d postgres -c 'CREATE ROLE app_role NOLOGIN'
# A quoted name with a space in it, because they exist and because a policy that
# names a role which cannot be recreated does not restore — leaving a table with
# row level security enabled and no policy on it.
psql -q -v ON_ERROR_STOP=1 -d postgres -c 'CREATE ROLE "Reporting Role" NOLOGIN'
for database in with_roles without_roles empty_table enabled_not_forced; do
  psql -q -v ON_ERROR_STOP=1 -d postgres -c "CREATE DATABASE $database"
  psql -q -v ON_ERROR_STOP=1 -d "$database" <<'SQL'
CREATE TABLE tenant_rows (
  id        bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL,
  payload   text NOT NULL
);
ALTER TABLE tenant_rows ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_rows
  USING (tenant_id::text = current_setting('app.tenant_id', true));
SQL
done

# Everything except enabled_not_forced is FORCED, which is the distinction the
# whole product turns on: enabled leaves the table owner exempt, forced does not.
for database in with_roles without_roles empty_table; do
  psql -q -v ON_ERROR_STOP=1 -d "$database" -c 'ALTER TABLE tenant_rows FORCE ROW LEVEL SECURITY'
done

# Policies that name roles. Before the agent learned to read a policy's own TO
# clause these did not restore at all, and what was left was a table with row
# level security enabled and no policy on it.
psql -q -v ON_ERROR_STOP=1 -d with_roles -c \
  "CREATE POLICY reporting_read ON tenant_rows FOR SELECT TO app_role, \"Reporting Role\" USING (true)"

# empty_table deliberately keeps no rows: that is the artefact under test.
for database in with_roles without_roles enabled_not_forced; do
  psql -q -v ON_ERROR_STOP=1 -d "$database" -c \
    "INSERT INTO tenant_rows (tenant_id, payload) SELECT gen_random_uuid(), repeat('x', 200) FROM generate_series(1, 20000)"
done

# The only difference between the first two artefacts.
psql -q -v ON_ERROR_STOP=1 -d with_roles -c 'GRANT SELECT, INSERT ON tenant_rows TO app_role'

pg_dump -Fc -d with_roles    -f /work/with-roles.dump
pg_dump -Fc -d without_roles -f /work/without-roles.dump
pg_dump -Fc -d empty_table   -f /work/empty-table.dump
pg_dump -Fc -d enabled_not_forced -f /work/enabled-not-forced.dump
note "with-roles.dump    $(du -h /work/with-roles.dump | cut -f1)"
note "without-roles.dump $(du -h /work/without-roles.dump | cut -f1)"
note "empty-table.dump   $(du -h /work/empty-table.dump | cut -f1)"

pg_ctl -D "$SRC_DATA" -m immediate stop >/dev/null 2>&1
rm -rf /work/source
unset PGHOST PGUSER
note "source cluster destroyed — neither app_role nor source exists anywhere now"

# ---------------------------------------------------------------------------
say "1. --dry-run restores nothing and says so"
# ---------------------------------------------------------------------------
proofdrill drill --dump-file /work/with-roles.dump --dry-run
expect "dry run reports it could not attempt" 2 "$?"

# ---------------------------------------------------------------------------
say "2. a real artefact passes level 1, and says what it cannot answer"
# ---------------------------------------------------------------------------
proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24
expect "drill passes level 1 on an artefact with a grant" 0 "$?"

proofdrill drill --dump-file /work/without-roles.dump --rpo-window-hours 24
expect "drill passes level 1 without a grant" 0 "$?"

# ---------------------------------------------------------------------------
say "2b. level 3 — the guarantees, and the enforcement behind them"
# ---------------------------------------------------------------------------
LEVEL3="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 --json)"
for key in rls_enabled_and_forced_preserved policies_identical grants_identical \
           row_level_security_actually_restricts; do
  if printf '%s' "$LEVEL3" | tr -d ' \n' | grep -q "\"key\":\"$key\",\"outcome\":\"passed\""; then
    printf '  [pass] %s\n' "$key"
  else
    printf '  [FAIL] %s did not pass\n' "$key"
    FAILURES=$((FAILURES + 1))
  fi
done

# The policy naming a quoted role must have survived; two policies went in.
if printf '%s' "$LEVEL3" | grep -q 'Reporting Role'; then
  printf '  [pass] a policy naming a quoted role survived the round trip\n'
else
  printf '  [FAIL] the policy naming "Reporting Role" is not in the report\n'
  FAILURES=$((FAILURES + 1))
fi

say "2c. enabled is not forced, and the report must not blur them"
proofdrill drill --dump-file /work/enabled-not-forced.dump --rpo-window-hours 24 \
  | grep -q "no table with row level security FORCED"
expect "an enabled but unforced table is named as such" 0 "$?"

# ---------------------------------------------------------------------------
say "3. a valid archive with no rows must FAIL — the founding failure"
# ---------------------------------------------------------------------------
proofdrill drill --dump-file /work/empty-table.dump --rpo-window-hours 24
expect "an empty but well formed archive is a failed drill" 1 "$?"

# ---------------------------------------------------------------------------
say "4. a backup older than its window must FAIL"
# ---------------------------------------------------------------------------
touch -d '3 days ago' /work/with-roles.dump
proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 >/dev/null
expect "an artefact outside the declared RPO window" 1 "$?"
touch /work/with-roles.dump

# ---------------------------------------------------------------------------
say "5. the JSON report, which is what the protocol will carry"
# ---------------------------------------------------------------------------
proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 --json
expect "json report" 0 "$?"

# ---------------------------------------------------------------------------
say "6. refusals that name the cause"
# ---------------------------------------------------------------------------
proofdrill drill --dump-file /work/does-not-exist.dump
expect "a missing artefact cannot be attempted" 2 "$?"

: > /work/empty.dump
proofdrill drill --dump-file /work/empty.dump
expect "a zero byte artefact cannot be attempted" 2 "$?"

proofdrill drill --dump-file /work/with-roles.dump --pg-major 99
expect "a major this image does not carry cannot be attempted" 2 "$?"

proofdrill drill --dump-file /work/with-roles.dump --not-an-option 1
expect "an unknown option is refused rather than ignored" 64 "$?"

# ---------------------------------------------------------------------------
say "7. nothing was left behind"
# ---------------------------------------------------------------------------
if [ -d /work/cluster ]; then
  printf '  [FAIL] /work/cluster survived the drill\n'
  FAILURES=$((FAILURES + 1))
else
  printf '  [pass] no cluster directory remains\n'
fi
note "work directory now holds: $(ls /work | tr '\n' ' ')"
note "disk used under /work: $(du -sh /work | cut -f1)"

printf '\n'
if [ "$FAILURES" -eq 0 ]; then
  printf 'VERIFICATION PASSED\n'
  exit 0
fi
printf 'VERIFICATION FAILED: %s check(s)\n' "$FAILURES"
exit 1
