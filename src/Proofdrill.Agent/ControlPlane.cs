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
internal sealed class ControlPlane(
    HttpClient http, Uri origin, string agentId, string token, PublishedKeys keys)
{
    /// <summary>
    /// Asks for work. Null means there is nothing to do, which is the normal
    /// answer and not a failure.
    /// <para>
    /// <b>The answer is checked before it is read.</b> It is counter-signed with
    /// the same key that counter-signs reports, published at
    /// <c>/api/v1/keys</c>, and an answer that does not verify — or that carries
    /// no signature at all — is refused rather than acted on. This does not
    /// replace TLS; it means that what a machine inside somebody's perimeter was
    /// told to do can be checked afterwards by somebody who was not there.
    /// </para>
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

        await VerifyAsync(document, cancellationToken).ConfigureAwait(false);

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
    /// Checks the control plane's counter-signature on an answer, including the
    /// one that says there is nothing to do.
    /// <para>
    /// <b>Every answer, and no exception for the empty one.</b> An answer that
    /// silences an agent for a night is as useful to a forger as one that sends
    /// it somewhere, and an agent that decides for itself when a signature is
    /// required has a downgrade path: strip the block, and it accepts.
    /// </para>
    /// </summary>
    private async Task VerifyAsync(JsonObject answer, CancellationToken cancellationToken)
    {
        if (answer["signature"] is not JsonObject signature
            || signature["value"]?.GetValue<string>() is not { Length: > 0 } value
            || signature["keyId"]?.GetValue<string>() is not { Length: > 0 } keyId)
        {
            throw new StorageException(
                "the control plane's answer carries no counter-signature. This agent will not act on an "
                + "instruction it cannot check, and a control plane that speaks this version of the job "
                + "protocol always signs.");
        }

        if (signature["algorithm"]?.GetValue<string>() is { } algorithm
            && algorithm != Signatures.CounterAlgorithm)
        {
            throw new StorageException(
                $"the control plane signed its answer with {algorithm}, and this build only checks "
                + $"{Signatures.CounterAlgorithm}.");
        }

        var key = await keys.ForAsync(keyId, cancellationToken).ConfigureAwait(false);

        if (!Signatures.VerifyCounterSignature(JobAnswer.SignedBytes(answer), key, value))
        {
            throw new StorageException(
                $"the control plane's answer does not verify against its published key '{keyId}'. Either it "
                + "was altered between there and here, or something that is not your control plane answered.");
        }
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
            // ReportJson.Format, because the control plane stores this text
            // verbatim and an evidence pack hands it to an auditor years later.
            // What goes on the wire is what somebody eventually reads.
            Content = new StringContent(
                envelope.ToJsonString(ReportJson.Format), Encoding.UTF8, "application/json"),
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
