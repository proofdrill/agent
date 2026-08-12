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
# Five artefacts, because a suite whose checks can only pass is decoration:
#
#   with-roles.dump        rows, forced RLS, a policy, a grant, and level 2's
#                          material: an extension, a foreign key, a check
#                          constraint, a function and a trigger  -> PASSES
#   without-roles.dump     the same without the grant             -> PASSES
#   enabled-not-forced.dump  RLS enabled and not forced           -> PASSES, and
#                          the report must not call that enforcement
#   empty-table.dump       a valid archive containing NO rows     -> FAILS
#   stale-sequence.dump    every row present and the sequence put
#                          back to the beginning                  -> FAILS
#
# The last two are the failures nothing else sees. An archive that is well
# formed, restores with exit code 0 and carries nothing is the product's
# founding failure; a sequence behind its own data restores just as cleanly and
# fails the next INSERT instead, weeks later, on a database somebody was told
# had been verified.
#
# NOT COVERED, and said here rather than discovered later: there is no test in
# which a level 2 or level 3 DDL comparison legitimately FAILS. Making one end
# to end needs a restore that loses a constraint or a guarantee, and every way of
# manufacturing that is either contrived or closed by the agent itself. The
# comparisons have been watched failing by hand — role ordering, before it was
# canonicalised — but that is not an assertion. Unit tests over SchemaDdl,
# SecurityDdl and Ddl.Difference are where that belongs.
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
for database in with_roles without_roles empty_table enabled_not_forced stale_sequence; do
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
for database in with_roles without_roles empty_table stale_sequence; do
  psql -q -v ON_ERROR_STOP=1 -d "$database" -c 'ALTER TABLE tenant_rows FORCE ROW LEVEL SECURITY'
done

# Level 2's material, and on with_roles alone: every other artefact here exists
# to make one particular check fail, and a fixture that changed under them would
# move what those cases prove.
psql -q -v ON_ERROR_STOP=1 -d with_roles <<'SQL'
CREATE EXTENSION pgcrypto;
CREATE TABLE customers (
  id   bigserial PRIMARY KEY,
  name text NOT NULL,
  CONSTRAINT customers_name_not_blank CHECK (length(name) > 0)
);
INSERT INTO customers (name) SELECT 'customer ' || g FROM generate_series(1, 50) AS g;
ALTER TABLE tenant_rows ADD COLUMN customer_id bigint REFERENCES customers (id);
-- The semicolons in this body are the point of it. A comparison that reads DDL
-- up to the first semicolon truncates both sides here at the same place, and
-- then reports a function whose body changed as identical.
CREATE FUNCTION stamp() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1;
  RETURN NEW;
END;
$$;
CREATE TRIGGER stamp_rows BEFORE UPDATE ON tenant_rows FOR EACH ROW EXECUTE FUNCTION stamp();
SQL

# Policies that name roles. Before the agent learned to read a policy's own TO
# clause these did not restore at all, and what was left was a table with row
# level security enabled and no policy on it.
psql -q -v ON_ERROR_STOP=1 -d with_roles -c \
  "CREATE POLICY reporting_read ON tenant_rows FOR SELECT TO app_role, \"Reporting Role\" USING (true)"

# empty_table deliberately keeps no rows: that is the artefact under test.
for database in with_roles without_roles enabled_not_forced stale_sequence; do
  psql -q -v ON_ERROR_STOP=1 -d "$database" -c \
    "INSERT INTO tenant_rows (tenant_id, payload) SELECT gen_random_uuid(), repeat('x', 200) FROM generate_series(1, 20000)"
done

# The only difference between the first two artefacts.
psql -q -v ON_ERROR_STOP=1 -d with_roles -c 'GRANT SELECT, INSERT ON tenant_rows TO app_role'

# And the only thing wrong with the fifth: the sequence is put back to the
# beginning while its 20000 rows stay where they are. This is not contrived —
# it is what a table copied by hand, or restored by a tool that does not carry
# the sequence, looks like afterwards.
psql -q -v ON_ERROR_STOP=1 -d stale_sequence \
  -c "SELECT setval('tenant_rows_id_seq', 1, false)" >/dev/null

pg_dump -Fc -d with_roles    -f /work/with-roles.dump
pg_dump -Fc -d without_roles -f /work/without-roles.dump
pg_dump -Fc -d empty_table   -f /work/empty-table.dump
pg_dump -Fc -d enabled_not_forced -f /work/enabled-not-forced.dump
pg_dump -Fc -d stale_sequence -f /work/stale-sequence.dump
note "with-roles.dump     $(du -h /work/with-roles.dump | cut -f1)"
note "without-roles.dump  $(du -h /work/without-roles.dump | cut -f1)"
note "empty-table.dump    $(du -h /work/empty-table.dump | cut -f1)"
note "stale-sequence.dump $(du -h /work/stale-sequence.dump | cut -f1)"

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
say "2d. level 2 — is it still that database?"
# ---------------------------------------------------------------------------
LEVEL2="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 --json)"
for key in extensions_present table_definitions_identical sequences_present \
           constraints_identical foreign_keys_identical functions_identical \
           triggers_identical sequences_ahead_of_their_data encoding_preserved; do
  if printf '%s' "$LEVEL2" | tr -d ' \n' | grep -q "\"key\":\"$key\",\"outcome\":\"passed\""; then
    printf '  [pass] %s\n' "$key"
  else
    printf '  [FAIL] %s did not pass\n' "$key"
    FAILURES=$((FAILURES + 1))
  fi
done

# functions_identical passing above is the whole of what this fixture can prove
# about the function: its body carries two semicolons, so a comparison that read
# DDL up to the first one would report a false DIFFERENCE here. The other
# direction — two bodies that differ below their first line compared EQUAL — is
# the dangerous one and it cannot be manufactured through a restore. It is
# asserted in the unit suite, over Ddl.Split and SchemaDdl.
note "the false-pass direction lives in the unit suite; a restore cannot produce it"

# ---------------------------------------------------------------------------
say "2e. a sequence behind its own data — the failure nothing else can see"
# ---------------------------------------------------------------------------
# pg_restore exits 0, all 20000 rows come back, every constraint is there, and
# the DDL matches the artefact exactly. The next INSERT fails with a duplicate
# key. Only asking the restored database finds it.
# Printed in full, like the empty archive below it: the sentence a customer
# reads when this fires is the whole value of the check, and a log that hides it
# cannot show that it says something usable.
proofdrill drill --dump-file /work/stale-sequence.dump --rpo-window-hours 24
expect "a sequence left behind its own data is a failed drill" 1 "$?"

# Captured first and grepped after, because pipefail makes the pipeline carry
# the drill's own exit code — which is 1 here, on purpose.
STALE="$(proofdrill drill --dump-file /work/stale-sequence.dump --rpo-window-hours 24 --json)"
printf '%s' "$STALE" | tr -d ' \n' | grep -q '"key":"sequences_ahead_of_their_data","outcome":"failed"'
expect "and that is the check that failed, by name" 0 "$?"

printf '%s' "$STALE" | tr -d ' \n' | grep -q '"key":"restore_exit_code","outcome":"passed"'
expect "while the restore itself exited clean, which is what makes it invisible" 0 "$?"

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
say "6b. the protocol, judged by openssl and not by us"
# ---------------------------------------------------------------------------
export PROOFDRILL_TOKEN=rh_agt_verification_token
proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 --envelope > /work/envelope.json
expect "a drill produces a signed envelope" 0 "$?"

proofdrill verify --report /work/envelope.json --agent >/dev/null
expect "the agent signature verifies with its own token" 0 "$?"

PROOFDRILL_TOKEN=somebody-elses proofdrill verify --report /work/envelope.json --agent >/dev/null 2>&1
expect "and does not verify with another token" 1 "$?"

# The independent half. openssl recomputes the HMAC over the same canonical
# bytes; if our canonicalisation and openssl's idea of HMAC-SHA256 disagree by
# one byte, these two strings differ.
proofdrill verify --report /work/envelope.json --agent --canonical-only > /work/agent.bin
CLAIMED="$(sed -n 's/.*"value": "\([^"]*\)".*/\1/p' /work/envelope.json | head -1)"
COMPUTED="$(openssl dgst -sha256 -mac HMAC -macopt "key:$PROOFDRILL_TOKEN" -binary /work/agent.bin \
            | base64 -w0 | tr '+/' '-_' | tr -d '=')"
if [ "$CLAIMED" = "$COMPUTED" ]; then
  printf '  [pass] openssl computes the same agent signature over the same canonical bytes\n'
else
  printf '  [FAIL] openssl disagrees: ours %s, openssl %s\n' "$CLAIMED" "$COMPUTED"
  FAILURES=$((FAILURES + 1))
fi

# And the counter-signature, with openssl standing in for the control plane —
# which is the whole point of choosing an asymmetric algorithm. If this works,
# §6 of the protocol is a recipe somebody can actually follow.
openssl ecparam -name prime256v1 -genkey -noout -out /work/private.pem 2>/dev/null
openssl ec -in /work/private.pem -pubout -out /work/public.pem 2>/dev/null

sed '1s/^{/{ "receipt": { "receivedAt": "2026-08-11T09:15:00Z", "reportId": "r1", "counterSignature": { "algorithm": "ECDSA-P256-SHA256", "keyId": "test" } },/' \
  /work/envelope.json > /work/receipted.json

proofdrill verify --report /work/receipted.json --canonical-only > /work/counter.bin
openssl dgst -sha256 -sign /work/private.pem -out /work/counter.der /work/counter.bin
SIGNATURE="$(base64 -w0 /work/counter.der | tr '+/' '-_' | tr -d '=')"
sed "s|\"keyId\": \"test\"|\"keyId\": \"test\", \"value\": \"$SIGNATURE\"|" \
  /work/receipted.json > /work/attested.json

proofdrill verify --report /work/attested.json --public-key /work/public.pem >/dev/null
expect "a counter-signature made by openssl verifies with our code" 0 "$?"

# The property the whole design rests on. The row count is changed to something
# flattering; the document stays perfectly well formed and the attestation fails.
sed 's/20000/1/' /work/attested.json > /work/tampered.json
proofdrill verify --report /work/tampered.json --public-key /work/public.pem >/dev/null 2>&1
expect "an edited report fails the attestation while staying well formed" 1 "$?"

# A report that was never received attests to nothing, and says so rather than
# looking like a failure.
proofdrill verify --report /work/envelope.json --public-key /work/public.pem >/dev/null 2>&1
expect "an envelope with no receipt cannot be checked" 2 "$?"

unset PROOFDRILL_TOKEN

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
