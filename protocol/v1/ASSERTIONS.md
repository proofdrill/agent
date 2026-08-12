# Your own SQL assertions, version 1

> The questions only you can ask, and what the agent will do with them.
>
> This document is in the open-source repository for the same reason
> [`PROTOCOL.md`](PROTOCOL.md) is, and with more force: it describes **text you
> write that a program runs inside your perimeter**, so the exact boundary
> around it has to be readable by the person who has to defend running it.

---

## 1. What an assertion is

One `SELECT` that must return **true**, with a sentence saying what is lost if
it does not.

```json
{
  "assertions": [
    {
      "key":   "app_role_sees_no_other_tenant",
      "title": "the application role cannot read another tenant's rows",
      "sql":   "SELECT count(*) = 0 FROM public.orders",
      "as":    "app_role",
      "settings": { "app.tenant_id": "00000000-0000-0000-0000-000000000000" }
    }
  ]
}
```

Levels 1 to 3 are derived from your artefact and hold for any database: the
restore happened, the schema is the same one, row level security is still
enabled *and forced* where it was, the policies and the grants are identical.
Assertions are the part nobody else can write for you — *this* view still hides
*that* column, *this* role sees nothing without a tenant, *that* table is never
empty in a real backup.

An assertion that returns false is a **failed drill**, exactly like a lost
policy. One that cannot run is a *could not attempt*: a correction, never a
verdict, and it never lowers the outcome.

## 2. The fields

| Field | Required | What it is |
|---|---|---|
| `key` | yes | Lower case letters, digits and underscores, starting with a letter, at most 48 characters. It becomes the line `assertion_<key>` in the report. |
| `title` | yes | Up to 200 characters, in the language of whoever reads the report. |
| `sql` | yes | One statement, at most 4096 characters, returning one row with one boolean column. |
| `as` | no | A role in the restored database to run it as. |
| `settings` | no | Up to ten session settings, applied before the statement. Values are strings. |

**`title` is not optional and will not become optional.** The person who reads a
drill report is usually not the person who wrote the SQL — they are filling in a
security questionnaire, and they cannot read a query. An assertion with no
sentence attached fails into silence.

**`as` is what turns a query into a demonstration.** Row level security is
evaluated against `current_user`, so *"the application role cannot read another
tenant's rows"* is only answered by becoming that role and trying. Asking the
catalogue would prove the policy exists, not that it bites.

**`settings` is how you put a policy in front of a tenant that does not exist.**
A policy reading `current_setting('app.tenant_id')` needs one to read; setting it
to an id nobody owns and asserting that nothing is visible is the check this
product exists for.

Whole packs are bounded too: **50 assertions**, **30 seconds** each, **10
minutes** for the pack. Going over any of them is reported, never silent —
assertions that did not run appear in the report saying so.

## 3. What they run as, which is the whole boundary

Every statement runs as a role the agent creates in the throwaway cluster for
this purpose:

```sql
CREATE ROLE proofdrill_assert
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS INHERIT;
GRANT pg_read_all_data TO proofdrill_assert;   -- PostgreSQL 14 and later
```

and inside `BEGIN READ ONLY` with a statement timeout.

Read what that role **cannot** do, because it is the answer to the obvious
question:

- **It is not a superuser**, so `COPY … FROM PROGRAM` and `COPY … TO FILE` are
  refused by the server. No statement in a pack can run a program or read a file
  on the machine the agent is installed on.
- **It is not a member** of `pg_execute_server_program`, `pg_read_server_files`
  or `pg_write_server_files`, and it cannot grant itself anything.
- **The transaction is read only**, so a pack cannot leave the third assertion
  quietly depending on what the second one did to the data.
- **The cluster has no TCP listener at all** and is deleted when the drill ends.
- **The agent's own secrets are not in the environment** the PostgreSQL server
  inherits: not the registration token, not the storage keys.

### Why the default is exempt from row level security, and `as` is not

`BYPASSRLS` in that list looks backwards for a product about row level security.
It is there because of which mistake it prevents.

An assertion with no `as` is asking about **data** — *this table is not empty*,
*no row lost its parent* — and everyone who buys this product has row level
security on the tables they would ask about. Without the exemption,
`SELECT count(*) = 0 FROM orders` reads zero rows *because a policy hid them*
and **passes**: a silent false pass, on the assertion somebody wrote precisely
because they did not trust the backup. It would also put two numbers that
contradict each other in one report, since the row counts in every report are
read with the same exemption.

Naming a role in `as` takes it away. `SET ROLE` changes `current_user`, and
PostgreSQL evaluates both the policies and the `BYPASSRLS` attribute against
`current_user` — so an assertion that names `app_role` is `app_role`, with
exactly the policies and exactly the grants that role has and nothing more.

The two together have a property worth stating plainly: **no arrangement of them
produces a false pass.** A data question written without `as` sees everything, as
intended. A guarantee question written with `as` sees what that role sees. And a
guarantee question written *without* `as` by mistake sees too much and comes back
**false** — a false alarm, which is the safe direction to be wrong in.

### `as`, and the one role that is refused

Naming a role in `as` grants it to `proofdrill_assert` so that `SET ROLE`
succeeds, with one exception: **a superuser is refused**, by name, and the
assertion is reported as one that could not be evaluated. Becoming a superuser
would hand a statement everything the list above takes away. Ask what a superuser
can do from the catalogue instead — levels 2 and 3 already do.

### There is no filter over your SQL, on purpose

Nothing inspects the statement looking for dangerous words. A filter that accepts
a language and forbids a subset of it is a promise that breaks on the first
function nobody thought of, and it would read as a guarantee in exactly the
document that must not contain one. **The boundary is the role, and the role is
enforced by PostgreSQL, not by us.**

The one shape rule is not a filter and does not pretend to be: the statement is
wrapped as `WITH … AS (<your sql>) SELECT * FROM …`, so anything that is not a
single query fails to parse and is reported as an assertion that could not be
evaluated.

## 4. Where the text comes from, and how to refuse it

Assertions are written **in the control plane**, because that is where the
history, the comparisons and the evidence pack live — an assertion whose verdict
nobody can date is not evidence of anything. They travel inside the job answer,
which is **counter-signed** with the control plane's published key
([`JOBS.md`](JOBS.md) §3.1): a pack altered between there and here is refused
before it is read, and a job whose pack does not parse is refused whole rather
than drilled without it.

Two switches stay on your side of the perimeter, and both are recorded in the
report rather than applied quietly:

```bash
# run this pack instead of whatever the control plane sends
proofdrill run --control-plane https://… --assertions /etc/proofdrill/pack.json

# run none of the assertions a job carries
proofdrill run --control-plane https://… --no-remote-assertions
```

And nothing needs a control plane at all:

```bash
proofdrill drill --dump-file db.dump --assertions pack.json
proofdrill doctor --s3-endpoint … --s3-bucket … --assertions pack.json   # checks the pack, restores nothing
```

## 5. What a verdict says, and what it never says

In the report, one assertion is one check at level 3:

```json
{
  "level": 3,
  "key": "assertion_app_role_sees_no_other_tenant",
  "outcome": "failed",
  "detail": "the application role cannot read another tenant's rows — did NOT hold (as app_role, with app.tenant_id set)"
}
```

Three things are **never** in it, and they are the reason this section exists:

- **Not your SQL.** The statement can carry an identifier, a literal, a tenant id
  — it is yours, and `PROTOCOL.md` §1 says what leaves your perimeter. The
  control plane already has any pack it sent; a pack from your own machine stays
  on your own machine.
- **Not a setting's value.** The report says `app.tenant_id` was set. It does not
  say to what.
- **Not PostgreSQL's error message.** An assertion that fails to run is reported
  with its **SQLSTATE** — `42501, insufficient_privilege` — because an error
  message can quote the row that caused it. The full message is printed on the
  terminal of the machine that ran the drill, and stays there.

## 6. Assertions worth writing first

Written as questions, because that is how they are usually discovered — somebody
asks *"would we notice?"* and nobody knows.

```json
{ "assertions": [
  {
    "key":   "tenant_isolation_holds_for_a_stranger",
    "title": "with an unknown tenant, the application role sees no rows at all",
    "sql":   "SELECT count(*) = 0 FROM public.orders",
    "as":    "app_role",
    "settings": { "app.tenant_id": "00000000-0000-0000-0000-000000000000" }
  },
  {
    "key":   "audit_trail_is_not_empty",
    "title": "the audit trail came back with rows in it",
    "sql":   "SELECT count(*) > 0 FROM public.audit_events"
  },
  {
    "key":   "no_customer_lost_their_organisation",
    "title": "every user still belongs to an organisation that exists",
    "sql":   "SELECT count(*) = 0 FROM public.users u LEFT JOIN public.organisations o ON o.id = u.organisation_id WHERE o.id IS NULL"
  },
  {
    "key":   "the_reporting_view_still_hides_salaries",
    "title": "the reporting view does not expose the salary column",
    "sql":   "SELECT count(*) = 0 FROM information_schema.columns WHERE table_name = 'reporting_people' AND column_name = 'salary'"
  }
] }
```

The last one is worth a note: it asks the restored database about its own shape
rather than its rows, and it is the cheapest kind of assertion to write and the
one people forget. A view that came back selecting `*` over a table that gained a
column is a disclosure, and it restores with exit code 0.
