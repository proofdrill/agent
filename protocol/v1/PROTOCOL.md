# Drill report protocol, version 1

> The document that leaves your perimeter, and the two signatures on it.
>
> This file is the contract. It lives in the open-source repository on purpose:
> the whole architecture rests on you being able to read exactly what we receive,
> and a protocol described only in a private codebase is a promise rather than a
> fact.

---

## 1. What is sent, and what is not

A report. Never a row of data, never a schema dump, never a connection string,
never a storage credential. The fields are enumerated in
[`report.schema.json`](report.schema.json) and there is no free-form container
anywhere in it — nothing is `additionalProperties`, so a future field cannot
smuggle content past a reader who checked this file.

Table names and row counts **are** in it, because a report that cannot say which
table lost rows is not a report. If that is more than your policy allows, the
agent is doing something you can read the source of, and this is the paragraph
to take to whoever sets the policy.

## 2. Two signatures, and they do different jobs

| | Who | What it proves | Who can check it |
|---|---|---|---|
| **Agent signature** | the agent, HMAC-SHA256 with its registration token | this report came from this agent and was not altered on the way | the control plane only |
| **Counter-signature** | the control plane, ECDSA P-256 over SHA-256 | **we received exactly this, at this moment** | anybody, with the public key |

The second is the evidence and the first is not. If only the agent signed, the
key would be in the customer's hands, and a report anybody could re-sign after
editing carries exactly as much weight as a Word document.

The counter-signature is **asymmetric on purpose**. An HMAC by the control plane
would be tamper-evident to us and unverifiable by anybody else, which is useless
for the one thing this product is for: handing a number to a third party who
does not take your word for it. With a published public key, an auditor checks
the report with `openssl` and no software of ours — §6.

## 3. Canonical form

Both signatures are over the same bytes, produced by these rules and no others:

1. UTF-8, no byte order mark.
2. Object keys sorted ascending by UTF-16 code unit, at every depth.
3. No whitespace between tokens.
4. Array order is preserved — it is data, not a set.
5. **No floating point anywhere in a signed payload.** Durations are integers of
   milliseconds, sizes are integers of bytes, ages are integers of seconds.
6. Timestamps are RFC 3339 in UTC with a `Z`, to the second.
7. Strings escape only what JSON requires, with `\uXXXX` for control characters,
   lower case hexadecimal.

Rule 5 is the one that looks arbitrary and is not. `0.1` does not have one
spelling across languages, and a protocol that signs a number a Go
implementation renders as `0.1` and a C# one renders as `0.10000000000000001`
has a signature that fails for a reason nobody will find. The canonicaliser
**refuses** to sign a payload containing a fractional number rather than
guessing a format.

## 4. The envelope

```json
{
  "protocolVersion": 1,
  "agent": { "id": "...", "version": "...", "hostname": "..." },
  "report": { ... },
  "agentSignature": {
    "algorithm": "HMAC-SHA256",
    "keyId": "the agent id",
    "value": "base64url, unpadded"
  }
}
```

The agent signature covers the canonical bytes of `protocolVersion`, `agent` and
`report` — everything except the signature block itself.

On receipt the control plane adds, and never modifies anything above:

```json
  "receipt": {
    "receivedAt": "2026-08-11T09:14:22Z",
    "reportId": "...",
    "counterSignature": {
      "algorithm": "ECDSA-P256-SHA256",
      "keyId": "the key that signed, so rotation does not invalidate history",
      "value": "base64url, unpadded"
    }
  }
```

The counter-signature covers the canonical bytes of the whole envelope
**including** `agentSignature` and including `receivedAt` and `reportId`, and
excluding only `counterSignature.value`. Signing the agent's signature is what
makes "this is the report that arrived" a statement rather than an assertion.

## 5. Versioning, and why old agents are permanent

`protocolVersion` is an integer and it is in the payload rather than in a header,
because **nothing auto-updates**. An agent that downloads and runs new code by
itself inside your perimeter is exactly what your own security questionnaire asks
you not to run, so we do not do it — which means an old agent is a permanent
fact and not a transitional one.

The support window is **declared and not inferred**: version 1 is supported until
at least **two years after version 2 is published**, and the control plane will
say so on the agent's page long before then. A version it no longer accepts is
refused with a message naming the version and the date, never with a parse error.

## 6. Verifying a report without any of our software

This is the point of the asymmetric counter-signature, so it gets a worked
recipe rather than a paragraph.

```bash
# 1. the canonical bytes that were signed
proofdrill verify --report report.json --canonical-only > canonical.bin

# 2. the signature, decoded
jq -r .receipt.counterSignature.value report.json \
  | tr '_-' '/+' | base64 -d > signature.der

# 3. the check, with nothing of ours involved
openssl dgst -sha256 -verify proofdrill-public-key.pem \
  -signature signature.der canonical.bin
```

`proofdrill verify` does the same thing and reports it in words. Both are
provided because an auditor who has to install our tool in order to check our
attestation has been given an attestation about an attestation.

## 7. What the control plane does not trust

Everything that decides money or scope is server-side, and the agent is told
rather than asked. A report naming a target that does not exist, or arriving
more often than the plan allows, or over a quota, is **rejected at ingestion** —
not counted and then billed for. The agent's copy of any limit is a convenience
for the person reading the terminal, never an enforcement point.

A modified agent can therefore run as many drills as it likes and none of them
will appear in an organisation's history, which is the only artefact that is ever
handed to an enterprise customer.
