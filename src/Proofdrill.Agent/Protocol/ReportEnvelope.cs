using System.Globalization;
using System.Text.Json.Nodes;

namespace Proofdrill.Agent.Protocol;

internal sealed record AgentIdentity(string Id, string Version, string Hostname);

/// <summary>
/// The document that leaves the customer's perimeter, built to
/// <c>protocol/v1/PROTOCOL.md</c>.
/// <para>
/// It is a separate shape from <see cref="DrillReport"/> on purpose. What the
/// terminal prints can be improved whenever somebody has a better sentence;
/// what is signed and sent is a contract that old agents will still be speaking
/// in two years, and the two changing together would be an accident waiting for
/// a release.
/// </para>
/// </summary>
internal static class ReportEnvelope
{
    public const int ProtocolVersion = 1;
    public const string TokenVariable = "PROOFDRILL_TOKEN";

    public static JsonObject Build(DrillReport report, AgentIdentity agent)
    {
        var checks = new JsonArray();
        foreach (var check in report.Level1)
        {
            checks.Add(Check(1, check));
        }

        foreach (var check in report.Level3)
        {
            checks.Add(Check(3, check));
        }

        var rowCounts = new JsonObject();
        foreach (var (table, count) in report.RowCounts)
        {
            rowCounts[table] = count;
        }

        return new JsonObject
        {
            ["protocolVersion"] = ProtocolVersion,
            ["agent"] = new JsonObject
            {
                ["id"] = agent.Id,
                ["version"] = agent.Version,
                ["hostname"] = agent.Hostname,
            },
            ["report"] = new JsonObject
            {
                ["outcome"] = report.Outcome,
                ["startedAt"] = Timestamp(report.StartedAt),
                ["postgresMajor"] = report.PostgresMajor,
                ["artefact"] = new JsonObject
                {
                    ["fileName"] = report.Artefact.FileName,
                    ["sizeBytes"] = report.Artefact.SizeBytes,
                    ["lastModified"] = Timestamp(report.Artefact.LastModified),
                    ["dumpedFromMajor"] = report.Artefact.DumpedFromMajor,
                },
                // Integers of the smallest unit, never fractions of an hour.
                // §3 rule 5: a canonical form has no portable spelling for 0.1.
                ["measuredRpoSeconds"] = Seconds(report.Measurements.MeasuredRpoHours * 3600),
                ["measuredRtoMilliseconds"] = Seconds(report.Measurements.MeasuredRtoSeconds * 1000),
                ["checks"] = checks,
                ["rowCounts"] = rowCounts,
                ["observations"] = Strings(report.Observations),
                ["notAttempted"] = Strings(report.NotAttempted),
            },
        };
    }

    /// <summary>
    /// Signs and attaches the agent's half. The signature covers everything above
    /// it and nothing else — a signature that covered itself would be a
    /// definition rather than a value.
    /// </summary>
    public static JsonObject Sign(JsonObject envelope, string agentId, string token)
    {
        envelope["agentSignature"] = new JsonObject
        {
            ["algorithm"] = Signatures.AgentAlgorithm,
            ["keyId"] = agentId,
            ["value"] = Signatures.SignAsAgent(AgentSignedBytes(envelope), token),
        };

        return envelope;
    }

    /// <summary>The bytes the agent signs: the envelope without any signature block.</summary>
    public static byte[] AgentSignedBytes(JsonObject envelope)
    {
        var body = (JsonObject)envelope.DeepClone();
        body.Remove("agentSignature");
        body.Remove("receipt");
        return CanonicalJson.Bytes(body);
    }

    /// <summary>
    /// The bytes the control plane counter-signs: the whole envelope, the agent's
    /// signature included, with only the counter-signature's own value removed.
    /// <para>
    /// Covering the agent's signature is what turns "this is a report" into "this
    /// is the report that arrived", which is the only claim worth attesting to.
    /// </para>
    /// </summary>
    public static byte[] CounterSignedBytes(JsonObject envelope)
    {
        var body = (JsonObject)envelope.DeepClone();
        if (body["receipt"]?["counterSignature"] is JsonObject signature)
        {
            signature.Remove("value");
        }

        return CanonicalJson.Bytes(body);
    }

    /// <summary>
    /// The token comes from the environment. Never an argument: a command line is
    /// readable by every process on the machine, and this one is the only thing
    /// standing between a stranger and an organisation's drill history.
    /// </summary>
    public static string Token() =>
        Environment.GetEnvironmentVariable(TokenVariable) is { Length: > 0 } token
            ? token
            : throw new UsageException(
                $"{TokenVariable} is not set. Reporting to a control plane needs the registration token, and it is " +
                "read from the environment because a command line is visible to every process on the machine.");

    private static JsonObject Check(int level, Check check) => new()
    {
        ["level"] = level,
        ["key"] = check.Key,
        ["outcome"] = check.Outcome,
        ["detail"] = check.Detail,
    };

    private static JsonArray Strings(IReadOnlyList<string> values)
    {
        var array = new JsonArray();
        foreach (var value in values)
        {
            array.Add(value);
        }

        return array;
    }

    private static JsonNode? Seconds(double? value) =>
        value is null ? null : JsonValue.Create((long)Math.Round(value.Value, MidpointRounding.AwayFromZero));

    /// <summary>RFC 3339, UTC, to the second. One spelling, everywhere.</summary>
    private static string Timestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
