# Proofdrill agent

> **Status: early development. There is no release and no published image.**
> `proofdrill drill` restores a `pg_dump -Fc` archive into a throwaway
> PostgreSQL and runs the **level 1, 2 and 3** assertions against it —
> including the **role attributes** read from your
> [`pg_dumpall --globals-only`](protocol/v1/GLOBALS.md) artefact, and **your own
> SQL assertions** ([how to write them](protocol/v1/ASSERTIONS.md)) — with
> measured RPO and RTO. It fetches from S3-compatible storage, and
> `proofdrill run` takes work from a control plane and reports back, signed.
> Whatever a run could not check is printed under its own heading every time,
> rather than left to be assumed.

Proofdrill proves that a database backup restores — and that the restored
database still enforces the guarantees the original enforced.

This repository holds **the part that runs on your machines**. It pulls a backup
artefact from your own storage, restores it into a throwaway PostgreSQL, checks
what survived, and sends back a report. The service that schedules the drills and
keeps their history never receives a row of your data.

## Why this is open source

Because you should not have to take our word for what runs inside your
infrastructure. The agent holds credentials to your backup storage and starts a
database from your data; both of those are things you are entitled to read before
you run them.

## How a drill will work

```
  1. pull the artefact from your storage    (your credentials, never ours)
  2. start a throwaway PostgreSQL
  3. restore into it
  4. run the assertion pack
  5. send back the signed report            (the report only — never the data)
  6. destroy everything it created
```

The assertions come in four levels. The first is what backup tooling usually
checks; the third is the one that matters and that nobody else does:

1. **Did the restore happen?** The artefact exists and is inside its window, the
   restore exits clean, the expected tables are there, the counts are within
   tolerance.
2. **Is it still that database?** The tables and their columns, the constraints,
   the foreign keys, the extensions, the functions and the triggers, each
   compared against what the archive itself declares. And every sequence is
   checked against the data it owns: one that came back at the beginning
   restores perfectly cleanly and fails your next insert.
3. **Do the guarantees still hold?** Row-level security enabled *and forced*
   where it was. Identical policies. No role your policies name is exempt from
   them — a role holding `BYPASSRLS` or `SUPERUSER` is read before any policy is,
   and that check needs your
   [cluster globals](protocol/v1/GLOBALS.md), because roles are not in a
   per-database backup. Your own SQL assertions still return true.
4. **The numbers you owe somebody.** Measured RPO from the age of the artefact,
   measured RTO from the real duration of the restore.

A backup that restores with every row in place and row-level security missing is
not a successful restore. It is a data breach with green counts.

## What this agent will never do

These are constraints on the design, not aspirations:

- **It never connects to your live database.** It reads a backup artefact and
  restores into a container it created.
- **It never sends your data anywhere.** Only the report leaves, and you can read
  the code that decides what goes into it.
- **It accepts no inbound connection.** It polls outward, so there is no port to
  open and no firewall change to request.
- **It needs no privileged access** — no Docker socket, no host root.
- **It does not update itself.** The service tells you when your agent is old;
  you decide when to replace it. Software that downloads and runs new code by
  itself, inside your perimeter, is what your own security questionnaire asks you
  not to run.
- **It cleans up after itself**, including after a failure, and runs under
  explicit resource limits. It is running on your machine, not ours.

## Running it

Against a file you already have, with no account and no network:

```
docker build -t proofdrill-agent .
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges \
  -v "$PWD:/artefacts:ro" proofdrill-agent \
  drill --dump-file /artefacts/your-backup.dump --rpo-window-hours 24
```

`--dry-run` reads the archive and restores nothing. `--json` prints the report
instead of the prose. The exit code is the contract: **0** passed, **1**
attempted and the backup did not hold, **2** could not be attempted — which is a
correction and not a verdict — **64** a bad command line, **70** the agent itself
broke, which says nothing about your backup.

Add `--globals-file globals.sql` and level 3 can answer the question it exists
for. Roles are cluster-wide: a per-database backup carries your policies and not
the roles they are written about, so without that second file the roles in the
restored database are placeholders and *"the application role is exempt from
every policy you wrote"* is invisible. One command produces it, and it does not
need a superuser:

```
pg_dumpall --globals-only --no-role-passwords -h HOST -U USER > globals-$(date +%F).sql
```

[`protocol/v1/GLOBALS.md`](protocol/v1/GLOBALS.md) says exactly what the agent
applies out of that file and what it refuses — the file is read, never executed.

Against your own bucket, downloading nothing:

```
docker run --rm --cap-drop=ALL \
  -e PROOFDRILL_S3_ACCESS_KEY_ID=... -e PROOFDRILL_S3_SECRET_ACCESS_KEY=... \
  proofdrill-agent doctor \
  --s3-endpoint https://s3.eu-central-1.amazonaws.com \
  --s3-bucket my-backups --s3-prefix nightly/ --s3-pattern 'db-*.dump'
```

`drill` takes the same storage options and fetches the newest matching artefact
itself. Credentials are read from the environment and are never accepted as
arguments: a command line is readable by every process on the machine.

When there is a release this becomes one `docker run` of a published image.

## The report, and the two signatures on it

What leaves your perimeter is defined in [`protocol/v1`](protocol/v1/PROTOCOL.md)
— the wire format, the canonical bytes, the signatures, and a worked example.

The agent signs to authenticate; **the control plane counter-signs and dates on
receipt, and that is the evidence.** The counter-signature is asymmetric on
purpose, so a report can be checked by somebody who trusts neither you nor us:

```
proofdrill verify --report report.json --control-plane https://your-control-plane
proofdrill verify --report report.json --public-key that-key.pem
```

Every report names the key that signed it, and the control plane publishes every
key it has ever signed with at `/api/v1/keys` — including the ones it has stopped
using, because a report is evidence for as long as the obligation it is about.
The first form fetches the right one; the second is for checking offline, with
the key that travelled inside an evidence pack.

The same check is three lines of `openssl` in §6 of the protocol, because an
auditor who has to install our tool in order to check our attestation has been
given an attestation about an attestation.

## Licence

See [LICENSE](LICENSE).
