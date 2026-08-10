# Spike 0 — what it answered

Run 2026-08-11, PostgreSQL 17.10 from PGDG, base `mcr.microsoft.com/dotnet/runtime:10.0`.

Container flags, because they are the claim rather than a detail:

```
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges --memory=512m --cpus=1
```

No Docker socket, no privileged mode, **every capability dropped**, uid 10001.

---

## 1. §10.2 option B is real — **Decided**

An unprivileged process can `initdb` its own cluster, start `postgres` as a child
process and restore into it, with no capabilities at all and 512 MB of memory.

| | |
|---|---|
| `initdb` | 3510 ms |
| `pg_dump -Fc`, 50 000 rows | 426 ms → 1.3 MB artefact |
| `pg_restore` | 413 ms |
| PostgreSQL 17 binaries in the image | **45 MB** |
| restored data directory | 71 MB |

**No TCP listener exists**, asserted positively rather than by reading a config:
a connection to `127.0.0.1:5432` is refused. `-h ''` is the load-bearing
argument, and the homepage sentence — *no privileged access, no Docker socket,
no inbound port* — is now true by construction.

### Correction, 2026-08-11, after building the real image

**That 45 MB measured the wrong thing**, and the corrected number is worth more
than the original. `du /usr/lib/postgresql` is the binaries directory alone; the
`postgresql-17` package installs **303 MB** once its shared libraries are
counted, and the finished agent image is **701 MB** with one major in it.

Where it goes:

| | |
|---|---|
| `/usr/lib/x86_64-linux-gnu` | 240 MB |
| — of which `libLLVM.so.19.1` | **123 MB** |
| `/usr/share/dotnet` | 80 MB |
| `/usr/lib/postgresql` (the binaries) | 45 MB |
| `/usr/share/postgresql` | 4 MB |

**LLVM is there for JIT compilation, and a restore never uses it.** It is 18% of
the image, and on an artefact that customers deliberately run vulnerability
scanners against, it is also 18% of the scanning surface — for a feature we do
not invoke. PostgreSQL loads its JIT provider only when `jit=on`, so setting
`jit=off` and dropping the library is a plausible 123 MB, and it is the next
cheap win rather than something done here on the way past.

The four-major matrix is still not 4 × 303 MB: the binaries are per major and
most of those libraries are shared. What it actually costs has to be measured by
installing the second major, not extrapolated — extrapolating is what produced
the wrong number the first time.

## 2. The finding: a plain `pg_dump` does not carry the authorization model

The source table had `ENABLE` **and** `FORCE ROW LEVEL SECURITY`, a policy, and
`GRANT SELECT, INSERT ... TO app_role`. Restored into a fresh cluster — which is
what a drill is, and why the spike destroys cluster A first:

| | source | restored |
|---|---|---|
| rows | 50 000 | **50 000** |
| RLS enabled / forced | true / true | **true / true** |
| policies | 1 | **1** |
| role `app_role` exists | yes | **no** |
| grants to `app_role` | 2 | **0** |

```
pg_restore: error: could not execute query: ERROR:  role "app_role" does not exist
Command was: GRANT SELECT,INSERT ON TABLE public.tenant_rows TO app_role;
pg_restore: warning: errors ignored on restore: 1
```

Roles are **cluster-wide**. `pg_dump` dumps one database and does not contain
them; they live in `pg_dumpall --globals-only`. So the artefact most teams
actually produce restores every row, keeps RLS forced, keeps the policies — and
arrives with **no roles and no grants**.

`pg_restore` exited **1** and said so. Anything that checks row counts sees
50 000 and reports success.

### What it changes, and it is not a code change

1. **Level 3's central assertion cannot be attempted on a `pg_dump`-only
   artefact.** *"The application role cannot read another tenant's rows"*
   requires that role to exist. It does not. Per §8.1 this is **could not
   attempt**, never **failed** — the distinction was designed before there was a
   case for it, and this is the first one.
2. **§7 minimum configuration needs a sixth field**: whether the target's backup
   includes globals, and where that second artefact lives. A team that has never
   restored will not know the answer, which is the whole premise of the product.
3. **`doctor` must find this before the first drill**, not the report afterwards.
   It is cheap: read the artefact's table of contents and say whether roles are
   in it.
4. **It is a sixth field failure for the launch article**, and the most
   demonstrable of them: thirty seconds, two clusters, and a restored database
   that has lost its entire authorization model with every row in place.

## 3. Not answered here, and not to be assumed

- **The ≥3× disk rule from §7 is still unmeasured.** 1.3 MB of artefact produced
  a 71 MB data directory, but almost all of that is the empty cluster's own
  floor. The ratio has to be measured on an artefact of realistic size before it
  is written on the installation page.
- **Collation.** Both clusters were `--locale=C`. Restoring into a different
  collation than the original is a real and quiet way to get wrong index
  ordering, and it belongs in level 2.
- **Peak memory during a large restore.** 512 MB held for a toy artefact; that
  number means nothing yet.
- **Extensions.** Nothing here used one. Missing extensions in the throwaway
  image are already on the risk list as the item that will break the estimates.
