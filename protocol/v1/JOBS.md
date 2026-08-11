# Proofdrill job protocol, version 1

How an agent asks a control plane for work. Public, for the same reason
`PROTOCOL.md` is: a protocol described only inside a private codebase is a
promise, and this one decides what a machine inside somebody's perimeter is
willing to be told to do.

It is a **separate document from the report**, deliberately. A report is
evidence — signed, stored, and verified by third parties years later, which is
why its schema forbids unknown fields at every level. A claim is a request: it is
never stored, nobody verifies one afterwards, and folding a field for it into the
report envelope would have meant changing a document other people have already
read.

---

## 1. The shape of the conversation

Two calls, both made **by the agent**. Nothing ever connects to the agent.

```
agent → POST /api/v1/agents/jobs/claim     "anything for me?"
       ← { "job": null }                   or a job
agent → POST /api/v1/agents/reports        the signed report, when the drill is done
```

No inbound port, no firewall rule, no long poll. The agent asks on an interval it
chooses; a connection held open for minutes through a corporate proxy is a
support conversation nobody needs.

## 2. The claim

```json
{
  "protocolVersion": 1,
  "agent": { "id": "0199a4c2-…", "version": "1.4.0", "hostname": "backup-host" },
  "claim": { "requestedAt": "2026-08-11T16:20:00Z" },
  "agentSignature": {
    "algorithm": "HMAC-SHA256",
    "keyId": "0199a4c2-…",
    "value": "base64url"
  }
}
```

**The signature is computed exactly as a report's is** (`PROTOCOL.md` §3): the
document is canonicalised with `agentSignature` removed — keys sorted ordinal at
every depth, no whitespace, UTF-8, no fractional numbers — and HMAC-SHA256'd with
the registration token. The token therefore never travels, on this call either.

`agent.id` and `agentSignature.keyId` are the id the control plane assigned at
registration. A hostname is not an id: the control plane resolves an organisation
from this value, and anything that is not a registered id is refused.

### 2.1 `requestedAt`, and why a request needs one

A signed document cannot usefully be replayed — it says what it says. A signed
**request** can: somebody who captures one can send it again. So a claim carries
the time it was made, and a control plane refuses one more than **five minutes**
from its own clock in either direction.

That window is not a substitute for TLS. It is what stops a recording from being
useful for ever, and it is short enough to matter and long enough for a machine
whose clock nobody has ever checked.

**Claiming is idempotent.** An agent that already holds a job gets the same job
back — from a retry, from a timeout reading the answer, or from a replay — rather
than taking a second one. An agent restoring two databases at once because a
proxy retried a POST is a failure this design refuses to make possible.

## 3. The answer

Nothing to do:

```json
{ "protocolVersion": 1, "job": null }
```

Something to do:

```json
{
  "protocolVersion": 1,
  "job": {
    "id": "0199a4c2-…",
    "target": { "id": "0199a4c2-…", "name": "production" },
    "storage": {
      "endpoint": "https://s3.eu-central-1.amazonaws.com",
      "bucket": "northwind-backups",
      "prefix": "daily/",
      "pattern": "db-*.dump",
      "region": "eu-central-1"
    },
    "postgresMajor": 17,
    "rpoWindowHours": 24,
    "leaseExpiresAt": "2026-08-11T22:20:00Z"
  }
}
```

**There are no credentials in a job, and there is no field for one.** It says
where to look; the read-only key that opens it is an environment variable on the
customer's machine and is never sent to us in the first place. A control plane
that could hand out storage credentials would be a control plane worth breaking
into.

`leaseExpiresAt` is when the control plane will assume the agent is gone and
offer the work again. It is renewed on every claim while a job is held, so an
agent still restoring a hundred gigabytes keeps it by continuing to poll.

## 4. Reporting against a job

The report is posted exactly as `PROTOCOL.md` describes, with one addition:

```
Proofdrill-Job-Id: 0199a4c2-…
```

**A header, and outside the signature on purpose.** The envelope carries what the
agent measured; which queue entry it answers is the control plane's bookkeeping,
and asking the agent to sign it would mean attesting to something it was told
rather than something it observed. The header is safe unsigned because of what it
is allowed to select: only a job the same agent already holds, resolved after the
signature has been checked.

A drill that **could not be attempted** is still reported, with
`outcome: "could_not_attempt"` and a level 1 check saying what stopped it. Staying
silent would leave the person who configured the target watching a queue that
empties into nothing.

## 5. Refusals

| Code | Meaning |
|---|---|
| `protocol_version_unsupported` | The control plane does not speak this version. Nothing auto-updates, so an old agent is a permanent fact and this is a sentence, not a parse error. |
| `claim_stale` | `requestedAt` is more than five minutes from the server's clock. |
| `claim_malformed`, `claim_unsigned` | The body is not a claim, or carries no usable signature block. |
| `claim_rejected` | Everything else, and **deliberately one answer**: an unknown agent, a revoked one and a bad signature are byte-identical, so an agent id on its own tells a stranger nothing. |

All are HTTP 400 with an RFC 9457 problem document carrying `code`.

## 6. What version 1 does not have

Said plainly, because a protocol's silences are read as promises:

- **No capability negotiation.** The job does not ask which PostgreSQL majors the
  agent has. A job for a major it cannot run is reported as
  `could_not_attempt` with a sentence naming it, which is visible to the customer
  — where a job filtered away silently would not be.
- **No signature on the answer.** A forged job would need TLS to be broken; when
  the public key list exists, the answer becomes counter-signed and this line
  goes away.
- **No cancellation.** A job an agent holds runs to completion or to its lease.
