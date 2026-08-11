using System.Text.Json;
using System.Text.Json.Serialization;

namespace Proofdrill.Agent;

/// <summary>
/// The three outcomes, and there are three rather than two on purpose.
/// <para>
/// <see cref="CouldNotAttempt"/> is not a softer <see cref="Failed"/>. It means
/// nothing was learned about the backup, so it moves the clock in neither
/// direction; <see cref="Failed"/> means the product did its job. Merging them
/// is the single easiest way to lose a customer at the exact moment the report
/// is worth the most to them.
/// </para>
/// </summary>
internal static class Outcome
{
    public const string Passed = "passed";
    public const string Failed = "failed";
    public const string CouldNotAttempt = "could_not_attempt";
}

internal sealed record Check(string Key, string Outcome, string Detail);

internal sealed record ArtefactFacts(
    string FileName,
    long SizeBytes,
    DateTimeOffset LastModified,
    double AgeHours,
    int? DumpedFromMajor);

/// <summary>Level 4: the two numbers somebody owes to a third party.</summary>
internal sealed record Measurements(double? MeasuredRpoHours, double? MeasuredRtoSeconds);

internal sealed record DrillReport(
    int ReportVersion,
    string Outcome,
    string AgentVersion,
    int? PostgresMajor,
    DateTimeOffset StartedAt,
    ArtefactFacts Artefact,
    Measurements Measurements,
    IReadOnlyList<Check> Level1,
    IReadOnlyList<Check> Level3,
    IReadOnlyDictionary<string, long> RowCounts,
    IReadOnlyList<string> Observations,
    IReadOnlyList<string> NotAttempted)
{
    /// <summary>
    /// Version 1, and it is in the payload rather than in a header because the
    /// control plane must tolerate old agents for ever: nothing auto-updates, so
    /// an old agent is a permanent fact and not a transitional one.
    /// </summary>
    public const int CurrentVersion = 1;

    public string ToJson() => JsonSerializer.Serialize(this, ReportJson.Format);
}

/// <summary>One shape for everything this agent prints as JSON.</summary>
internal static class ReportJson
{
    public static readonly JsonSerializerOptions Format = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };
}
