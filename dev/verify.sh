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
# and three cluster globals artefacts, because roles are cluster-wide and none of
# the five above contains one:
#
#   globals.sql            the roles as they are, one of them legitimately
#                          holding BYPASSRLS                      -> PASSES
#   globals-exempt.sql     the same cluster one ALTER later, with
#                          BYPASSRLS on the role a policy names   -> FAILS
#   globals-early.sql      dumped before one of the roles existed -> FAILS
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
#
# A customer assertion CAN fail here, and one does. with-roles.dump carries a
# second policy that permits app_role to read every row, which defeats the tenant
# isolation the first policy describes — while every derived comparison passes,
# because the restored database's policies really are identical to the artefact's.
# That is the case levels 1 to 3 cannot see and the customer's own SQL can, and it
# is asserted end to end in 2f and 2g.
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

# The legitimate BYPASSRLS role, and it is here as a NEGATIVE control. Whoever
# takes the backup has to be exempt from row level security or the dump comes
# back empty — the founding failure — so a check that fired on any role holding
# BYPASSRLS would cry wolf on every correctly configured cluster in the world.
# No policy names this one, and level 3 must stay quiet about it.
psql -q -v ON_ERROR_STOP=1 -d postgres -c \
  "CREATE ROLE backup_role LOGIN BYPASSRLS PASSWORD 'not-a-real-password'"
psql -q -v ON_ERROR_STOP=1 -d postgres -c 'GRANT pg_read_all_data TO app_role'
# Applied to nothing: membership of the machine-access roles is refused by name,
# because an assertion can name a role in its `as` and ASSERTIONS.md §3 promises
# a statement cannot read a file on the host.
psql -q -v ON_ERROR_STOP=1 -d postgres -c 'GRANT pg_read_server_files TO backup_role'
# Two statements a globals artefact routinely carries and this agent never runs.
psql -q -v ON_ERROR_STOP=1 -d postgres -c 'ALTER ROLE app_role SET search_path TO public'
mkdir -p /work/ts
psql -q -v ON_ERROR_STOP=1 -d postgres -c "CREATE TABLESPACE spare LOCATION '/work/ts'"

# The globals as they stood BEFORE the reporting role existed. Written to a file
# on purpose: it is a globals artefact older than the backup beside it, which is
# what a nightly job that dumps the roles weekly produces, and the drill has to
# notice that the two artefacts no longer describe the same cluster.
pg_dumpall --globals-only > /work/globals-early.sql

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

# The cluster globals, dumped WITHOUT --no-role-passwords on purpose: the file
# therefore carries a SCRAM verifier, and a later check asserts that no part of
# it reaches the report. GLOBALS.md recommends --no-role-passwords to customers
# for the opposite reason — a file with no secret in it needs no protecting.
pg_dumpall --globals-only > /work/globals.sql

# And the same cluster one ALTER later. This is not contrived: granting BYPASSRLS
# to the application role is what somebody does at four in the afternoon to make
# a permissions problem go away, and it silently ends every policy written about
# that role. The backup does not change; the artefact beside it does.
psql -q -v ON_ERROR_STOP=1 -d postgres -c 'ALTER ROLE app_role BYPASSRLS'
pg_dumpall --globals-only > /work/globals-exempt.sql
psql -q -v ON_ERROR_STOP=1 -d postgres -c 'ALTER ROLE app_role NOBYPASSRLS'

pg_dump -Fc -d with_roles    -f /work/with-roles.dump
pg_dump -Fc -d without_roles -f /work/without-roles.dump
pg_dump -Fc -d empty_table   -f /work/empty-table.dump
pg_dump -Fc -d enabled_not_forced -f /work/enabled-not-forced.dump
pg_dump -Fc -d stale_sequence -f /work/stale-sequence.dump
note "with-roles.dump     $(du -h /work/with-roles.dump | cut -f1)"
note "without-roles.dump  $(du -h /work/without-roles.dump | cut -f1)"
note "empty-table.dump    $(du -h /work/empty-table.dump | cut -f1)"
note "stale-sequence.dump $(du -h /work/stale-sequence.dump | cut -f1)"

note "globals.sql          $(du -h /work/globals.sql | cut -f1)"

pg_ctl -D "$SRC_DATA" -m immediate stop >/dev/null 2>&1
rm -rf /work/source /work/ts
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
say "2f. your own SQL assertions — and the hole the derived checks cannot see"
# ---------------------------------------------------------------------------
# The fixture carries two policies: tenant_isolation, which is what everybody
# believes is protecting the table, and reporting_read, which permits app_role to
# SELECT everything. Permissive policies are OR'd, so the second one silently
# defeats the first — and every derived check passes, because the restored
# database's policies are identical to the artefact's. They ARE identical. The
# database was always like this.
#
# Only somebody who knows what app_role is for can ask the question, which is the
# entire argument for this feature existing.

cat > /work/pack-holds.json <<'JSON'
{
  "assertions": [
    {
      "key": "the_owner_sees_nothing_for_a_stranger",
      "title": "with an unknown tenant, the table owner sees no rows at all",
      "sql": "SELECT count(*) = 0 FROM public.tenant_rows",
      "as": "source",
      "settings": { "app.tenant_id": "00000000-0000-0000-0000-000000000000" }
    },
    {
      "key": "the_customers_table_is_not_empty",
      "title": "the customers table came back with rows in it",
      "sql": "SELECT count(*) > 0 FROM public.customers"
    },
    {
      "key": "the_protected_table_is_not_empty",
      "title": "the tenant table came back with rows in it",
      "sql": "SELECT count(*) > 0 FROM public.tenant_rows"
    },
    {
      "key": "no_customer_carries_the_placeholder_name",
      "title": "no customer record was left holding a placeholder name",
      "sql": "SELECT count(*) = 0 FROM public.customers WHERE name = 'zzz-canary-in-the-sql'"
    }
  ]
}
JSON

HOLDS="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
         --assertions /work/pack-holds.json --json)"
expect "a pack whose assertions hold is a passed drill" 0 "$?"

# The pair on the SAME forced table is the semantics, asserted rather than
# described: with no `as`, an assertion asks about the data and sees all 20000
# rows; with `as`, it becomes that role and the policy hides every one of them.
# If the exemption survived SET ROLE, the first of these would pass and the
# second would fail — and this product would be reporting isolation it does not
# have.
for key in assertion_the_owner_sees_nothing_for_a_stranger assertion_the_customers_table_is_not_empty \
           assertion_the_protected_table_is_not_empty assertion_no_customer_carries_the_placeholder_name; do
  if printf '%s' "$HOLDS" | tr -d ' \n' | grep -q "\"key\":\"$key\",\"outcome\":\"passed\""; then
    printf '  [pass] %s\n' "$key"
  else
    printf '  [FAIL] %s did not pass\n' "$key"
    FAILURES=$((FAILURES + 1))
  fi
done

# The line that used to say "not implemented yet" on every single run.
if printf '%s' "$HOLDS" | grep -q 'customer SQL assertions: not implemented'; then
  printf '  [FAIL] the report still says customer assertions are not implemented\n'
  FAILURES=$((FAILURES + 1))
else
  printf '  [pass] no report claims customer assertions are unimplemented\n'
fi

say "2g. an assertion that does not hold is a FAILED drill"
cat > /work/pack-fails.json <<'JSON'
{
  "assertions": [
    {
      "key": "app_role_sees_no_other_tenant",
      "title": "the application role cannot read another tenant's rows",
      "sql": "SELECT count(*) = 0 FROM public.tenant_rows",
      "as": "app_role",
      "settings": { "app.tenant_id": "00000000-0000-0000-0000-000000000000" }
    }
  ]
}
JSON

proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
  --assertions /work/pack-fails.json
expect "an assertion that returns false fails the drill" 1 "$?"

BROKEN="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
          --assertions /work/pack-fails.json --json)"

printf '%s' "$BROKEN" | tr -d ' \n' | grep -q '"key":"assertion_app_role_sees_no_other_tenant","outcome":"failed"'
expect "and it is that assertion, by name" 0 "$?"

# The whole point, stated as a check: every derived guarantee comparison passes
# on the same run. The policies came back identical, the RLS statements came back
# identical, and the application role can still read every tenant's rows.
for key in rls_enabled_and_forced_preserved policies_identical grants_identical; do
  printf '%s' "$BROKEN" | tr -d ' \n' | grep -q "\"key\":\"$key\",\"outcome\":\"passed\""
  expect "$key still passes on the failed drill" 0 "$?"
done

say "2h. the boundary is the role, and it is the server that holds it"
cat > /work/pack-bounded.json <<'JSON'
{
  "assertions": [
    {
      "key": "reading_a_file_from_the_host",
      "title": "an assertion cannot read a file on the machine the agent runs on",
      "sql": "SELECT pg_read_file('/etc/hostname') IS NOT NULL"
    },
    {
      "key": "listing_a_directory_on_the_host",
      "title": "an assertion cannot list a directory on the machine the agent runs on",
      "sql": "SELECT count(*) > 0 FROM pg_ls_dir('/')"
    },
    {
      "key": "running_as_the_cluster_superuser",
      "title": "an assertion cannot ask to run as a superuser",
      "sql": "SELECT true",
      "as": "proofdrill"
    },
    {
      "key": "asking_for_a_role_that_does_not_exist",
      "title": "an assertion naming a role the artefact never carried",
      "sql": "SELECT true",
      "as": "no_such_role_anywhere"
    },
    {
      "key": "returning_something_that_is_not_a_verdict",
      "title": "an assertion that returns a number instead of true or false",
      "sql": "SELECT count(*) FROM public.customers"
    }
  ]
}
JSON

BOUNDED="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
           --assertions /work/pack-bounded.json --json)"
expect "none of the bounded assertions is a verdict, so the drill still passes" 0 "$?"

for key in assertion_reading_a_file_from_the_host assertion_listing_a_directory_on_the_host \
           assertion_running_as_the_cluster_superuser assertion_asking_for_a_role_that_does_not_exist \
           assertion_returning_something_that_is_not_a_verdict; do
  if printf '%s' "$BOUNDED" | tr -d ' \n' | grep -q "\"key\":\"$key\",\"outcome\":\"could_not_attempt\""; then
    printf '  [pass] %s could not be attempted\n' "$key"
  else
    printf '  [FAIL] %s did not come back as could_not_attempt\n' "$key"
    FAILURES=$((FAILURES + 1))
  fi
done

# The privilege refusal is reported as a code and never as PostgreSQL's own
# sentence, because an error message can quote the row that caused it.
printf '%s' "$BOUNDED" | grep -q 'SQLSTATE 42501'
expect "the file read is refused by the server, reported as SQLSTATE 42501" 0 "$?"

printf '%s' "$BOUNDED" | grep -q 'is a superuser in the restored cluster'
expect "and a superuser is refused by name before anything runs" 0 "$?"

# What must NOT be in the report: the statements themselves. The control plane
# already has any pack it sent, and a pack from this machine stays on it.
for text in pg_read_file pg_ls_dir; do
  if printf '%s' "$BOUNDED" | grep -q "$text"; then
    printf '  [FAIL] the report carries the assertion SQL: %s\n' "$text"
    FAILURES=$((FAILURES + 1))
  else
    printf '  [pass] the report does not carry the SQL (%s)\n' "$text"
  fi
done

# The case that matters most, because it is how a customer's own data ends up
# inside an assertion in the first place: a literal in the WHERE clause. It is in
# the pack, it is not in the report, and the report is the thing that leaves.
if printf '%s' "$HOLDS" | grep -q 'zzz-canary-in-the-sql'; then
  printf '  [FAIL] a literal from the assertion SQL reached the report\n'
  FAILURES=$((FAILURES + 1))
else
  printf '  [pass] a literal inside an assertion does not reach the report\n'
fi

# Nor the value of a setting. The report says which parameter was set, never to
# what: a value is written by the customer and can be anything out of their data.
if printf '%s' "$HOLDS" | grep -q '00000000-0000-0000-0000-000000000000'; then
  printf '  [FAIL] the report carries a setting value\n'
  FAILURES=$((FAILURES + 1))
else
  printf '  [pass] the report names app.tenant_id without saying what it was set to\n'
fi

say "2i. a pack that is wrong is refused before anything is restored"
printf '{ "assertions": [ { "key": "no_title", "sql": "SELECT true" } ] }' > /work/pack-bad.json
proofdrill drill --dump-file /work/with-roles.dump --assertions /work/pack-bad.json
expect "an assertion with no title is a usage error" 64 "$?"

printf 'not json at all' > /work/pack-broken.json
proofdrill drill --dump-file /work/with-roles.dump --assertions /work/pack-broken.json
expect "a pack that is not JSON is a usage error" 64 "$?"

proofdrill drill --dump-file /work/with-roles.dump --assertions /work/does-not-exist.json
expect "a pack that is not there is a usage error" 64 "$?"

# ---------------------------------------------------------------------------
say "2j. the cluster globals — the roles a per-database backup does not carry"
# ---------------------------------------------------------------------------
# Everything above this line drilled a database whose roles were placeholders
# this agent invented so the restore could finish. The second artefact is what
# turns them into the customer's own roles, and it is the whole of what makes
# level 3's central question answerable.

GLOBALS="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
           --globals-file /work/globals.sql --json)"
expect "a drill with the cluster globals still passes" 0 "$?"

for key in roles_present_with_their_attributes globals_carry_every_role_the_backup_uses \
           no_role_is_exempt_from_a_policy_that_names_it; do
  if printf '%s' "$GLOBALS" | tr -d ' \n' | grep -q "\"key\":\"$key\",\"outcome\":\"passed\""; then
    printf '  [pass] %s\n' "$key"
  else
    printf '  [FAIL] %s did not pass\n' "$key"
    FAILURES=$((FAILURES + 1))
  fi
done

# The negative control. backup_role holds BYPASSRLS legitimately — whoever takes
# the dump must, or it comes back empty — and no policy names it, so the check
# above passed WITH an exempt role in the cluster. A check that fired here would
# be useless the day it shipped.
if printf '%s' "$GLOBALS" | grep -q 'backup_role (LOGIN, BYPASSRLS)'; then
  printf '  [pass] the legitimate BYPASSRLS role is reported and is not a verdict\n'
else
  printf '  [FAIL] backup_role is not named in the observations\n'
  FAILURES=$((FAILURES + 1))
fi

# What must not be in the report, and the file it came from had one in it: this
# globals artefact was dumped WITHOUT --no-role-passwords, so it carries a SCRAM
# verifier for backup_role. The agent drops it rather than loading it.
for secret in SCRAM 'not-a-real-password'; do
  if printf '%s' "$GLOBALS" | grep -q "$secret"; then
    printf '  [FAIL] the report carries something out of the globals file: %s\n' "$secret"
    FAILURES=$((FAILURES + 1))
  else
    printf '  [pass] no password verifier reaches the report (%s)\n' "$secret"
  fi
done

# The two statements that are in every real globals file and must never run here.
printf '%s' "$GLOBALS" | grep -q 'tablespace statement'
expect "a CREATE TABLESPACE is refused and said out loud" 0 "$?"
printf '%s' "$GLOBALS" | grep -q 'per-role setting'
expect "an ALTER ROLE ... SET is refused and said out loud" 0 "$?"
printf '%s' "$GLOBALS" | grep -q 'machine-access'
expect "membership of pg_read_server_files is refused by name" 0 "$?"

# And the line every run used to print, which was the honest admission that the
# product's headline check could not be made.
if printf '%s' "$GLOBALS" | grep -q 'Add the pg_dumpall --globals-only artefact'; then
  printf '  [FAIL] the report still asks for a globals artefact it was given\n'
  FAILURES=$((FAILURES + 1))
else
  printf '  [pass] the report no longer asks for the artefact it has\n'
fi

# The enforcement probe sees something it could not see before, and it is worth
# its own check: these tables are owned by `source`, which the globals declare a
# superuser. A superuser is never subject to row level security, so the pass this
# same probe reports without the globals — where the owner is a placeholder that
# is not a superuser — was describing a role that does not exist in production.
printf '%s' "$GLOBALS" | tr -d ' \n' \
  | grep -q '"key":"row_level_security_actually_restricts","outcome":"could_not_attempt"'
expect "a forced table owned by a superuser is not reported as restrained" 0 "$?"
printf '%s' "$GLOBALS" | grep -q 'owned by a superuser'
expect "and the sentence says why, rather than blaming the policy" 0 "$?"

say "2k. one ALTER on one role, and the same backup FAILS"
# The point of the whole feature, end to end. Same artefact, same policies, same
# 20000 rows — and a globals file in which app_role holds BYPASSRLS. Every check
# derived from the backup still passes, because the backup really is intact. The
# policies naming that role cannot bite, and only the second artefact can say so.
proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
  --globals-file /work/globals-exempt.sql >/dev/null
expect "a role a policy names holding BYPASSRLS is a failed drill" 1 "$?"

EXEMPT="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
          --globals-file /work/globals-exempt.sql --json)"

printf '%s' "$EXEMPT" | tr -d ' \n' \
  | grep -q '"key":"no_role_is_exempt_from_a_policy_that_names_it","outcome":"failed"'
expect "and it is that check, by name" 0 "$?"

printf '%s' "$EXEMPT" | grep -q 'app_role (BYPASSRLS)'
expect "naming the role and the attribute that ended the policy" 0 "$?"

for key in restore_exit_code restored_database_not_empty; do
  printf '%s' "$EXEMPT" | tr -d ' \n' | grep -q "\"key\":\"$key\",\"outcome\":\"passed\""
  expect "$key still passes on the failed drill" 0 "$?"
done
for key in rls_enabled_and_forced_preserved policies_identical grants_identical; do
  printf '%s' "$EXEMPT" | tr -d ' \n' | grep -q "\"key\":\"$key\",\"outcome\":\"passed\""
  expect "$key still passes on the failed drill" 0 "$?"
done

say "2l. two artefacts that no longer describe the same cluster"
# globals-early.sql was dumped before "Reporting Role" existed — which is what a
# weekly role dump beside a nightly backup produces. The restored database has
# objects belonging to a role the globals artefact never mentions, and the drill
# has to say so rather than quietly inventing it again.
STALE_GLOBALS="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
                 --globals-file /work/globals-early.sql --json)"

printf '%s' "$STALE_GLOBALS" | tr -d ' \n' \
  | grep -q '"key":"globals_carry_every_role_the_backup_uses","outcome":"failed"'
expect "a globals artefact missing a role the backup uses is a failed drill" 0 "$?"

printf '%s' "$STALE_GLOBALS" | grep -q 'Reporting Role'
expect "and the role it does not declare is named" 0 "$?"

say "2m. an assertion naming a role that turns out to be a superuser"
# pack-holds.json asks what the table owner can see, as `source`. Without the
# globals that is a placeholder and the question is answerable. With them it is
# the superuser it always was in production, and the refusal IS the answer.
SUPER="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
         --assertions /work/pack-holds.json --globals-file /work/globals.sql --json)"

printf '%s' "$SUPER" | tr -d ' \n' \
  | grep -q '"key":"assertion_the_owner_sees_nothing_for_a_stranger","outcome":"could_not_attempt"'
expect "an assertion naming a superuser is refused rather than run" 0 "$?"
printf '%s' "$SUPER" | grep -q 'your own cluster globals say it is one'
expect "and the refusal is the answer, not an obstacle" 0 "$?"

say "2n. a globals pattern pointed at the wrong object"
# The mistake a customer makes once: the pattern matches something that is not a
# pg_dumpall --globals-only artefact. The drill goes on — this says nothing about
# whether the backup restores — and the report says the roles are placeholders.
WRONG="$(proofdrill drill --dump-file /work/with-roles.dump --rpo-window-hours 24 \
         --globals-file /work/pack-holds.json --json)"
expect "a globals file that is not one does not stop the drill" 0 "$?"
printf '%s' "$WRONG" | grep -q 'carries no role this agent recognises'
expect "and it is named as the reason the roles are placeholders" 0 "$?"

proofdrill drill --dump-file /work/with-roles.dump --globals-file /work/nowhere.sql
expect "a globals file that is not there is a usage error" 64 "$?"

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
say "6a. the other half of that refusal: a major this image DOES carry"
# ---------------------------------------------------------------------------
# The check above proves the agent says no to a major it lacks. On its own that
# is satisfied by an agent that says no to everything except the newest thing
# installed — which is exactly the defect a multi-major image exists to remove,
# and the one every other fixture here is blind to, because they are all written
# by the newest major.
#
# So: an artefact written by the OLDEST major in the image, drilled with no
# --pg-major at all. It passes only if the agent read the version out of the
# archive's own table of contents and reached for those binaries.
MAJORS="$(ls /usr/lib/postgresql | sort -n)"
NEWEST_MAJOR="$(printf '%s' "$MAJORS" | tail -1)"
note "this image carries: $(printf '%s' "$MAJORS" | tr '\n' ' ')"

# EVERY major, not the two ends. The image's claim is a list, the refusal above
# quotes that list back to the customer, and a major that is installed but
# cannot actually drill would be a lie told in the one message a customer reads
# when their drill did not happen. Each pass costs an initdb, a 20 000 row
# insert and a dump — seconds — which is cheap for the only check that covers
# what the packaging promises.
for major in $MAJORS; do
  PG_MAJOR="$major" /usr/local/bin/make-fixture.sh "/work/major-${major}.dump"
  REPORT="$(proofdrill drill --dump-file "/work/major-${major}.dump" --rpo-window-hours 24 --json)"
  expect "an artefact from PostgreSQL ${major} drills (newest here is ${NEWEST_MAJOR})" 0 "$?"

  # And the report says which server wrote it. A customer reading a report about
  # a database they did not restore themselves has no other way to tell that the
  # matching binaries were used — and "it restored" is exactly what a mismatched
  # pg_restore can also say, right up to the parts it silently did not bring.
  if printf '%s' "$REPORT" | tr -d ' \n' | grep -q "\"postgresMajor\":${major}"; then
    printf '  [pass] the report names PostgreSQL %s as the writer\n' "$major"
  else
    printf '  [FAIL] the report does not name PostgreSQL %s as the writer\n' "$major"
    FAILURES=$((FAILURES + 1))
  fi

  rm -f "/work/major-${major}.dump"
done

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
