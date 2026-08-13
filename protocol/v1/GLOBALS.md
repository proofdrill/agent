# The cluster globals, version 1

> The second artefact, why there has to be one, and exactly what this agent does
> with a file of SQL out of your own bucket.
>
> This document is in the open-source repository for the same reason
> [`ASSERTIONS.md`](ASSERTIONS.md) is: it describes **a file you wrote that a
> program applies inside your perimeter**, so the boundary around it has to be
> readable by the person who has to defend running it.

---

## 1. Why one backup file is not enough, and it is not your fault

A `pg_dump` of a database carries the rows, the schema, the policies and
`FORCE ROW LEVEL SECURITY`. It does **not** carry the roles those policies are
written about, because roles are a property of the *cluster* and not of the
database — they live in `pg_dumpall --globals-only`, and nothing warns you.

So a per-database backup restored on its own gives you this:

```
  every row present            ✓
  every policy identical       ✓
  row level security forced    ✓
  the roles the policies name  — invented by the restore, empty, attributes unknown
```

Every one of those ticks is real and the last line makes them worth nothing on
its own. `app_role` in the restored database is a name this agent created so that
`ALTER TABLE … OWNER TO app_role` would not fail; whether the *real* `app_role`
holds `BYPASSRLS` — and is therefore exempt from every policy you wrote — is not
in the file and cannot be worked out from it.

That is why a target has a sixth field, and why it is the one most people cannot
answer the first time they are asked.

## 2. How to produce one

```bash
pg_dumpall --globals-only --no-role-passwords -l DBNAME -h HOST -U USER > globals-$(date +%F).sql
```

Put it in the same bucket and under the same prefix as the backup, on the same
schedule, and name it in the target's globals pattern — `globals-*.sql`. It is a
few kilobytes; the cost of writing one nightly is nothing.

**`-l DBNAME` is what makes this work on a managed provider**, and it is the
step most people hit first. `pg_dumpall` has to connect somewhere before it can
read anything cluster-wide, and left to itself it opens `postgres`, falling back
to `template1`. On a hosted PostgreSQL your role often may not open either:

```
pg_dumpall: error: connection to server at "..." failed:
FATAL:  pg_hba.conf rejects connection for host "...", user "...",
        database "template1", SSL encryption
```

That message names a database you did not ask for and a file you have never
edited, so it reads as a firewall problem or a wrong password. It is neither.
`-l` points it at a database your role can already open — the one you are backing
up will do — and the roles it reads are the same either way, because roles are
cluster-wide and do not belong to the database you happened to connect through.

**`--no-role-passwords` is the recommendation and not a detail.** Without it,
`pg_dumpall` reads `pg_authid` and writes every role's password verifier into the
file — which means the file needs a superuser to produce and becomes a secret to
store. With it, the same file is produced by any role that can read `pg_roles`,
and there is no verifier in it to protect. This agent drops the verifiers
anyway (§3); not writing them is better than us dropping them.

## 3. What the agent applies, and what it refuses

**The file is read. It is never executed.** What runs against the throwaway
cluster is a list of statements this agent composed from what it recognised, and
the difference is not stylistic — three kinds of statement in a perfectly
ordinary globals file must not run on the machine the agent is installed on.

| From your file | What happens | Why |
|---|---|---|
| `CREATE ROLE` / `ALTER ROLE … WITH` | **Applied**, as all seven attributes: `SUPERUSER`, `INHERIT`, `CREATEROLE`, `CREATEDB`, `LOGIN`, `REPLICATION`, `BYPASSRLS` | They are what level 3 asks about, and nothing is left to a default |
| `GRANT <role> TO <role>` | **Applied**, keeping `WITH INHERIT` and `WITH SET`, dropping `GRANTED BY` | The grantor here is the drill's own superuser, exactly as it would be for any restore into a cluster your roles never existed in |
| `PASSWORD 'SCRAM-SHA-256$…'`, `VALID UNTIL`, `CONNECTION LIMIT` | **Dropped** | No report can carry them and the cluster has no listener to authenticate anybody against, so loading them would be holding a secret with no use for it |
| `CREATE TABLESPACE … LOCATION '/mnt/fast'` | **Refused** | A tablespace is a directory on your machine, outside the drill's working directory. This agent asks you for read-only credentials and does not behave as though it had more |
| `ALTER ROLE … SET <parameter>` | **Refused** | That assigns a server parameter, and some parameters name a library for the server to load. A drill answers questions about a backup; it does not load code because a file said so |
| `GRANT pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program` | **Refused**, by name | [`ASSERTIONS.md`](ASSERTIONS.md) §3 promises a customer statement cannot reach the machine, and an assertion names a role in its `as`. That promise does not move because a globals file grants something |
| Anything else | **Refused**, and counted | A statement nobody has read the shape of is not applied on the strength of looking harmless |

Every refusal is **in the report**, under what the run did not check. A reader
told that the globals were applied would otherwise assume all of them were.

Two smaller rules, for completeness: a role named `proofdrill` or
`proofdrill_assert` is not applied to — rewriting the drill's own credentials
half way through is not a thing to discover afterwards — and neither is any name
beginning with `pg_`, which PostgreSQL reserves.

`GRANT pg_read_all_data TO app_role` **is** applied, and the distinction is worth
stating: it grants `SELECT` on every table and it does **not** exempt anybody from
row level security. A role that has it in production has it here, and the
policies still apply to it.

## 4. What it makes answerable

With the globals applied, three things in the report change from a sentence about
what could not be checked into a check:

- **`no_role_is_exempt_from_a_policy_that_names_it`** (level 3). Read from
  `pg_policy.polroles` in the restored database: every role a policy names, and
  whether it holds `BYPASSRLS` or `SUPERUSER`. **A policy that names a role
  exists in order to restrain that role**, and both of those attributes are read
  before any policy is. A database can come back with every row in place, every
  policy byte-identical to the artefact's, forced row level security on every
  table, and the policies still cannot bite. That is a **failed drill**, and
  nothing derived from the per-database artefact can see it.
- **`roles_present_with_their_attributes`** (level 2). What your file declared,
  against what `pg_roles` holds after it was applied.
- **`globals_carry_every_role_the_backup_uses`** (level 2). The two artefacts are
  a pair, and this is the check that says so. A globals file older than the
  backup beside it, a truncated one, and one taken from a different cluster all
  look the same from here: a restored database whose objects belong to roles the
  globals artefact never mentioned.

And one thing changes that is not a check. An assertion that names a role in its
`as` ([`ASSERTIONS.md`](ASSERTIONS.md) §2) becomes **that role, as your own
cluster declares it** — with its attributes and its memberships — instead of an
empty placeholder of the same name. Without the globals, every report carrying
such an assertion says so, which is honest and is not the same as answering the
question.

The enforcement probe gets more precise too, in a direction that is only visible
once the roles are real: a forced table whose owner is a **superuser** is
reported as one no policy can restrain. `FORCE ROW LEVEL SECURITY` exists to
subject a table's owner to its policies, and it cannot subject that one.

## 5. What it still does not answer

Said plainly, because a document's silences are read as promises:

- **Nothing about passwords.** Whether a role can still authenticate, and with
  what, is not asked and cannot be: the verifiers are dropped and the throwaway
  cluster has no listener.
- **Nothing about per-role parameters.** A role whose production `search_path`
  puts a schema first does not have it here (§3), so an assertion should name its
  schema — `public.orders`, not `orders`.
- **Nothing about tablespaces.** If your objects live in one, the restore fails on
  them and level 1 says so; the tablespace itself is not created.
- **Whether the two artefacts are the same age.** The report states how much older
  or newer the globals file is than the backup, and leaves the judgement to you.
  The check that would catch a badly mismatched pair is
  `globals_carry_every_role_the_backup_uses`, and it only sees a role that went
  missing — not one whose attributes changed after the file was written.

## 6. Where the agent gets it

Three ways, and they are the same three every input to this agent has:

```bash
# from a file you already have
proofdrill drill --dump-file db.dump --globals-file globals.sql

# from the same bucket and prefix as the backup, matched by its own pattern
proofdrill drill --s3-endpoint … --s3-bucket … --s3-globals-pattern 'globals-*.sql'

# from the target's configuration, which is where it belongs
proofdrill run --control-plane https://…
```

In the third form the control plane sends the answer with the job — `JOBS.md`
§3.3 — and it is **data and not text to run**: it names an object in a bucket the
agent already has read-only credentials for, and everything in this document
still applies to what comes back.

`--globals-file` wins over a pattern, for the same reason `--assertions` wins over
a pack the control plane sent: a file somebody named by hand is not overridden by
something found in a bucket.

The object is refused **before it is downloaded** if it is larger than 16 MiB. A
globals artefact is a few kilobytes of `CREATE ROLE`; a pattern that has matched
something enormous has matched the wrong object, and finding that out at the far
end of somebody's egress bill is not a diagnosis.

## 7. What never leaves your perimeter

The same rule as everywhere else in this protocol, applied to this file:

- **Not the file.** Nothing of its text is sent anywhere.
- **Not a password verifier**, which is never even loaded.
- **Not a per-role parameter's value.**

Role **names** and their **attributes** do appear in the report, because a report
that cannot say *which* role is exempt from your policies is not a report — the
same reasoning `PROTOCOL.md` §1 gives for table names and row counts. If that is
more than your policy allows, the agent is doing something you can read the source
of, and this is the paragraph to take to whoever sets the policy.
