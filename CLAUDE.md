# Proofdrill agent — working agreement

> The half of Proofdrill that runs on **other people's machines**.

The control plane's `CLAUDE.md` is the product contract and still applies: what
this product is, who buys it, the four assertion levels. This file is only what
is **different here**, and the difference is not small.

---

## 1. The three facts that decide everything else

**It runs inside somebody else's infrastructure.** Not our server, not our
uptime, not our disk. Every design argument that begins "it would be convenient
if" ends here.

**It is read before it is run.** This repository goes public at the first
release, and the person who reads it is the same person who has to defend
running it to their own security review. Code that would embarrass us in that
reading is a product defect, not a style question.

**It is the distribution channel, not the product.** Somebody can run every
drill they like locally and never pay. That is expected and it is fine — the
paid thing is the dated, counter-signed history, and it lives in the control
plane. Nothing here is ever crippled to protect revenue: no licence check, no
phone-home, no obfuscation. See `docs/03` §12 in the control plane.

---

## 2. The six promises `README.md` already makes in public

They are constraints, not aspirations, and they were published before any code
existed. Breaking one is a breaking change to the product:

1. **Never connects to the live database.** It reads an artefact and restores
   into a cluster it created.
2. **Never sends data anywhere.** Only the report leaves, and what goes into the
   report is readable in the code that builds it.
3. **Accepts no inbound connection.** It polls outward. No port, no firewall
   request, no conversation with their IT department.
4. **Needs no privileged access** — no Docker socket, no host root. Proven by
   spike 0: it runs with `--cap-drop=ALL` and starts its own PostgreSQL as a
   child process. `spike/FINDINGS.md`.
5. **Does not update itself.** The control plane says an agent is old; the
   customer replaces it. Software that downloads and executes new code by itself
   inside a perimeter is what the questionnaire we are helping them fill in asks
   them not to run.
6. **Cleans up after itself, including after a failure**, and runs under
   explicit limits.

---

## 3. Engineering rules

Rule 10 of the control plane's list is this repository's whole charter, so it is
expanded rather than repeated.

1. **Guaranteed cleanup, on every path.** Every cluster, directory and temporary
   file is removed on success, on failure, on an exception and on a signal. A
   drill that leaves a data directory behind fills somebody's disk one night per
   week, and the failure will be attributed to us correctly.
2. **Disk and memory are checked before the work, not during it.** Refusing to
   start is a good outcome. Dying halfway through a restore with a full disk is
   the one mistake this product cannot afford, because it happens on their
   machine and it is our name on it.
3. **`--dry-run` is honest or it is worse than absent.** It must state what it
   did *not* do. A dry run that quietly performs a subset teaches people to
   distrust the flag exactly when they are being careful.
4. **Never write to the artefact, its bucket, or anything outside the work
   directory.** Read-only credentials are what we ask for; behaving as though we
   had more is how that request stops being believed.
5. **Fail loudly and specifically.** "Restore failed" is not a message. Name the
   artefact, the exit code, the stage. The person reading it has never restored
   this backup before — that is why they bought the product.
6. **A drill that could not be attempted is not a drill that failed**, and the
   two are separate in the report's data model, never merged in a status field
   later. `docs/03` §8.1.
7. **Assert from the catalogue, not from a privileged read.** The agent is
   superuser of its own throwaway cluster, and a superuser bypasses RLS — so
   "I could read the table" proves nothing. Read `pg_class`, `pg_policies`,
   `pg_roles`; and where behaviour is the claim, `SET ROLE` to the role in
   question and try.
8. **Parse machine output, not messages.** Exit codes and `pg_restore --list`,
   never the English text of an error. Messages are localised and they change
   between majors.

---

## 4. The protocol between the two repositories

**There is no shared package, and there will not be one.** Two independent
implementations that agree are evidence; one shared type both sides compile
against proves nothing about the wire — which is the same reason the control
plane computes TOTP and Stripe's HMAC independently in its own tests.

- The report's **JSON Schema and its golden examples live here**, versioned,
  because this is the repository the customer can read and the report is what
  leaves their perimeter.
- The control plane keeps a copy of those fixtures and a test that fails when
  they drift.
- **The protocol is versioned from the first commit**, with a support window
  written on the installation page. The control plane must tolerate old agents:
  nothing auto-updates, so old agents are permanent, not transitional.

---

## 5. How we work

Same as the control plane, and worth restating only where it bites here.

- **Italian in conversation with Luigi. English in everything else** — code,
  commits, comments, documentation, and every string a user sees.
- **Small logical commits.** **Luigi pushes, always** — stop at the commit and
  say it is ready.
- **PowerShell syntax** for any command handed to Luigi. The product's own
  commands are `docker run`, and the installation page carries **two** variants,
  because a customer on Docker Desktop needs backticks where Linux needs
  backslashes.
- **Rigorous honesty about state.** "Implemented" and "verified" are different
  words and the difference is always stated.

### Verification standard

**Compiling is not evidence. Run it in the container.** The precedent is spike
0, which was written to answer a design question and answered a product one
instead — because it ran. Two clusters, the first destroyed before restoring,
and a `pg_dump` that turned out not to carry the roles.

A drill is verified when it has run against a **real artefact** produced by a
**different** cluster than the one it restores into. Restoring into the cluster
that produced the dump proves nothing about roles, grants or ownership, because
those are cluster-wide and were never in the file.

---

## 6. Sources of truth

| Question | Where |
|---|---|
| What the agent is, its subcommands, what we distribute, plan limits | control plane, `docs/03-pitch-and-agent.md` §6-§12 |
| What spike 0 established and measured | `spike/FINDINGS.md` |
| What the product is and who buys it | control plane, `CLAUDE.md` |
| Where the whole thing stands, honestly | control plane, `STATUS.md` |
