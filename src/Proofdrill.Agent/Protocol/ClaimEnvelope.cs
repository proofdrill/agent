using System.Globalization;
using System.Text.Json.Nodes;

namespace Proofdrill.Agent.Protocol;

/// <summary>
/// How this agent asks for work — <c>protocol/v1/JOBS.md</c>, and a separate
/// document from the report on purpose.
/// <para>
/// The report describes evidence and is published with
/// <c>additionalProperties: false</c> at every level; a poll is a request, it is
/// never stored, and nobody will verify one afterwards. Folding a field for it
/// into the report envelope would have meant changing a document other people
/// have already read.
/// </para>
/// <para>
/// It is signed with the same token and the same canonical form as a report, so
/// the registration token still never leaves this machine. The one thing a
/// request needs that a document does not is a timestamp: a signed document
/// cannot usefully be replayed, and a signed request can.
/// </para>
/// </summary>
internal static class ClaimEnvelope
{
    public const int ProtocolVersion = 1;

    public static JsonObject Build(AgentIdentity agent, DateTimeOffset requestedAt) => new()
    {
        ["protocolVersion"] = ProtocolVersion,
        ["agent"] = new JsonObject
        {
            ["id"] = agent.Id,
            ["version"] = agent.Version,
            ["hostname"] = agent.Hostname,
        },
        ["claim"] = new JsonObject
        {
            // RFC 3339, UTC, to the second — one spelling everywhere, and the
            // control plane refuses one more than five minutes from its own clock.
            ["requestedAt"] = requestedAt.ToUniversalTime()
                .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
        },
    };

    public static JsonObject Sign(JsonObject claim, string agentId, string token)
    {
        claim["agentSignature"] = new JsonObject
        {
            ["algorithm"] = Signatures.AgentAlgorithm,
            ["keyId"] = agentId,
            ["value"] = Signatures.SignAsAgent(SignedBytes(claim), token),
        };

        return claim;
    }

    /// <summary>The bytes signed: the request without its signature block.</summary>
    public static byte[] SignedBytes(JsonObject claim)
    {
        var body = (JsonObject)claim.DeepClone();
        body.Remove("agentSignature");
        return CanonicalJson.Bytes(body);
    }
}
