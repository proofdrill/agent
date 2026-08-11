using System.Text.Json.Nodes;

namespace Proofdrill.Agent.Protocol;

/// <summary>
/// What comes back from a claim — <c>protocol/v1/JOBS.md</c> §3 — and the
/// signature over it.
/// <para>
/// Version 1 of that document said the answer was unsigned, and said why: a
/// forged job would need TLS to be broken, and there was nowhere to publish the
/// key that would check one. Both halves shipped together the moment there was,
/// and this agent <b>requires</b> the signature rather than accepting an answer
/// without one. Compatibility runs one way here: old agents are permanent,
/// because nothing auto-updates, and old control planes are not — there is one,
/// and we deploy it.
/// </para>
/// </summary>
internal static class JobAnswer
{
    /// <summary>
    /// The bytes the control plane signed: the whole answer with only the
    /// signature's own value removed. The same rule as a report's receipt, so
    /// there is one canonicalisation on this side and not two.
    /// </summary>
    public static byte[] SignedBytes(JsonObject answer)
    {
        var body = (JsonObject)answer.DeepClone();
        if (body["signature"] is JsonObject signature)
        {
            signature.Remove("value");
        }

        return CanonicalJson.Bytes(body);
    }
}
