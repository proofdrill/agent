using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Proofdrill.Agent.Protocol;
using Proofdrill.Agent.Storage;

namespace Proofdrill.Agent;

/// <summary>One drill, as the control plane handed it over.</summary>
internal sealed record AssignedJob(
    string Id,
    string TargetName,
    StorageOptions Storage,
    int? PostgresMajor,
    double? RpoWindowHours);

/// <summary>
/// The only conversation this agent has with anything of ours, and it is entirely
/// outbound: ask for work, send back a report. Nothing listens on this machine —
/// no port is opened, no firewall rule is needed, and the decision to connect is
/// always the customer's.
/// <para>
/// Both calls are authenticated by signing with the registration token, so the
/// token itself never travels. There is no session, no bearer header and nothing
/// to steal from a proxy log.
/// </para>
/// </summary>
internal sealed class ControlPlane(HttpClient http, Uri origin, string agentId, string token)
{
    /// <summary>
    /// Asks for work. Null means there is nothing to do, which is the normal
    /// answer and not a failure.
    /// </summary>
    public async Task<AssignedJob?> ClaimAsync(AgentIdentity identity, CancellationToken cancellationToken)
    {
        var claim = ClaimEnvelope.Sign(
            ClaimEnvelope.Build(identity, DateTimeOffset.UtcNow), agentId, token);

        using var body = new StringContent(claim.ToJsonString(), Encoding.UTF8, "application/json");
        using var response = await http
            .PostAsync(new Uri(origin, "/api/v1/agents/jobs/claim"), body, cancellationToken)
            .ConfigureAwait(false);

        var answer = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            // Named, with whatever the control plane said. The three refusals it
            // gives on purpose are identical — an agent id tells a stranger
            // nothing — but a version it no longer speaks, or a clock that is
            // hours out, say so, and those are the two a person can fix.
            throw new StorageException(
                $"the control plane refused the claim: HTTP {(int)response.StatusCode}. {answer.Trim()}");
        }

        if (JsonNode.Parse(answer) is not JsonObject document)
        {
            throw new StorageException("the control plane answered a claim with something that is not JSON.");
        }

        if (document["job"] is not JsonObject job)
        {
            return null;
        }

        var storage = job["storage"]!;
        var endpoint = new Uri(storage["endpoint"]!.GetValue<string>());

        return new AssignedJob(
            Id: job["id"]!.GetValue<string>(),
            TargetName: job["target"]?["name"]?.GetValue<string>() ?? "a database",
            Storage: new StorageOptions(
                Endpoint: endpoint,
                Bucket: storage["bucket"]!.GetValue<string>(),
                Prefix: storage["prefix"]?.GetValue<string>() ?? "",
                Pattern: storage["pattern"]?.GetValue<string>() ?? "*",
                Region: storage["region"]?.GetValue<string>() ?? "us-east-1",

                // The same heuristic the command line uses, because a job and a
                // hand-typed run must address the same bucket the same way.
                PathStyle: !endpoint.Host.EndsWith("amazonaws.com", StringComparison.OrdinalIgnoreCase)),
            PostgresMajor: (int?)job["postgresMajor"]?.GetValue<int>(),
            RpoWindowHours: (double?)job["rpoWindowHours"]?.GetValue<int>());
    }

    /// <summary>
    /// Sends the report, saying which job it answers.
    /// <para>
    /// The job id travels in a header and not inside the envelope, because the
    /// envelope is the evidence: it carries what this agent measured, and being
    /// told which queue entry to answer is not a measurement. The signature covers
    /// the measurement; the header only picks, among this agent's own jobs, the
    /// one being closed.
    /// </para>
    /// </summary>
    public async Task PostReportAsync(JsonObject envelope, string? jobId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, "/api/v1/agents/reports"))
        {
            Content = new StringContent(envelope.ToJsonString(), Encoding.UTF8, "application/json"),
        };

        if (jobId is not null)
        {
            request.Headers.TryAddWithoutValidation("Proofdrill-Job-Id", jobId);
        }

        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("proofdrill", DrillRunner.AgentVersion()));

        using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var answer = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            // Never silently: a drill whose report did not arrive is a drill that
            // did not happen as far as anybody reading the history is concerned.
            throw new StorageException(
                $"the report was not accepted: HTTP {(int)response.StatusCode}. {answer.Trim()}");
        }
    }
}
