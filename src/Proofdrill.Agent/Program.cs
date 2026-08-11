using System.Runtime.InteropServices;
using System.Text.Json;
using Proofdrill.Agent;
using Proofdrill.Agent.Protocol;
using Proofdrill.Agent.Storage;

// Exit codes are a contract, because people put this in cron and read $?:
//
//   0   the drill passed
//   1   the drill was attempted and the backup did not hold
//   2   the drill could NOT be attempted — a correction, not a verdict
//   64  the command line was wrong
//   70  the agent itself broke, which is our defect and not the backup's
const int Passed = 0, Failed = 1, CouldNotAttempt = 2, UsageError = 64, InternalError = 70;

using var stopping = new CancellationTokenSource();

// Cleanup has to survive an interrupt: a drill stopped with ctrl-C or by a
// container being told to stop must still remove its cluster and its data
// directory. Cancelling the token unwinds through the `await using`, which is
// where the removal lives.
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stopping.Cancel();
};
using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
{
    context.Cancel = true;
    stopping.Cancel();
});

try
{
    var command = CommandLine.Parse(args);

    if (command.Has("--help"))
    {
        Help();
        return Passed;
    }

    switch (command.Command)
    {
        case "drill":
            return await DrillAsync(command, stopping.Token).ConfigureAwait(false);

        case "version":
            Console.WriteLine($"proofdrill {DrillRunner.AgentVersion()}");
            Console.WriteLine($"PostgreSQL majors available: {Majors()}");
            return Passed;

        case "doctor":
            return await DoctorAsync(command, stopping.Token).ConfigureAwait(false);

        case "verify":
            return await VerifyAsync(command, stopping.Token).ConfigureAwait(false);

        case "run":
            return await RunAsync(command, stopping.Token).ConfigureAwait(false);

        default:
            await Console.Error.WriteLineAsync($"proofdrill: unknown subcommand '{command.Command}'")
                .ConfigureAwait(false);
            Help();
            return UsageError;
    }
}
catch (UsageException exception)
{
    await Console.Error.WriteLineAsync($"proofdrill: {exception.Message}").ConfigureAwait(false);
    Help();
    return UsageError;
}
catch (DrillCannotBeAttemptedException exception)
{
    await Console.Error.WriteLineAsync($"proofdrill: the drill could not be attempted. {exception.Message}")
        .ConfigureAwait(false);
    return CouldNotAttempt;
}
catch (StorageException exception)
{
    // Also a correction rather than a verdict: a key that is too narrow, an
    // endpoint that is wrong or a bucket that cannot be reached says nothing at
    // all about whether the backup behind it would restore.
    await Console.Error.WriteLineAsync($"proofdrill: {exception.Message}").ConfigureAwait(false);
    return CouldNotAttempt;
}
catch (HttpRequestException exception)
{
    await Console.Error.WriteLineAsync(
        $"proofdrill: the storage endpoint could not be reached. {exception.Message}").ConfigureAwait(false);
    return CouldNotAttempt;
}
catch (OperationCanceledException)
{
    await Console.Error.WriteLineAsync("proofdrill: stopped on request. Everything it created has been removed.")
        .ConfigureAwait(false);
    return CouldNotAttempt;
}
catch (Exception exception)
{
    // Never a bare stack trace as the only trace: this runs where nobody is
    // watching, and an unhandled failure that reads like a backup failure would
    // be the worst possible confusion for this product to cause.
    await Console.Error.WriteLineAsync($"proofdrill: the agent failed, and this says nothing about your backup.")
        .ConfigureAwait(false);
    await Console.Error.WriteLineAsync(exception.ToString()).ConfigureAwait(false);
    return InternalError;
}

// The command an auditor runs, and the reason the counter-signature is
// asymmetric. It checks OUR attestation, so it takes a public key and needs
// nothing else of ours — §6 of the protocol prints the same check as three
// lines of openssl, on purpose.
async Task<int> VerifyAsync(CommandLine command, CancellationToken cancellationToken)
{
    var envelope = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(command.Required("--report")))
        as System.Text.Json.Nodes.JsonObject
        ?? throw new UsageException("that file does not contain a report envelope");

    // --agent selects the other signature. Both are exposed because both have a
    // reader: the counter-signature is checked by whoever was handed the report,
    // and the agent signature is checked by whoever is debugging why the control
    // plane refused one.
    var forAgent = command.Has("--agent");
    var canonical = forAgent
        ? ReportEnvelope.AgentSignedBytes(envelope)
        : ReportEnvelope.CounterSignedBytes(envelope);

    if (command.Has("--canonical-only"))
    {
        using var stdout = Console.OpenStandardOutput();
        stdout.Write(canonical);
        return Passed;
    }

    if (forAgent)
    {
        var claimed = envelope["agentSignature"]?["value"]?.GetValue<string>()
            ?? throw new UsageException("that report carries no agent signature");

        if (!Signatures.VerifyAgent(canonical, ReportEnvelope.Token(), claimed))
        {
            Console.Error.WriteLine("proofdrill: the agent signature does not verify against this token.");
            return Failed;
        }

        Console.WriteLine("  VERIFIED   the agent signature matches this token");
        return Passed;
    }

    var signature = envelope["receipt"]?["counterSignature"]?["value"]?.GetValue<string>();
    if (signature is null)
    {
        Console.Error.WriteLine(
            "proofdrill: this report has no counter-signature. It was produced by an agent and never received by " +
            "a control plane, so it attests to nothing beyond the machine that made it.");
        return CouldNotAttempt;
    }

    // Which key signed this one. It is in the report because keys get rotated and
    // a report has to stay verifiable after its own key is replaced — so this is
    // what decides which key to fetch, rather than "the current one", which is
    // the wrong answer for everything older than the last rotation.
    var keyId = envelope["receipt"]?["counterSignature"]?["keyId"]?.GetValue<string>();

    string pem;

    if (command.Value("--public-key") is { } keyPath)
    {
        pem = File.ReadAllText(keyPath);
    }
    else if (command.Value("--control-plane") is { } origin)
    {
        if (keyId is null)
        {
            Console.Error.WriteLine("proofdrill: that receipt does not say which key signed it.");
            return CouldNotAttempt;
        }

        // Fetched by id from the list the control plane publishes — one request,
        // and the same one an auditor would make by hand with curl. The list
        // keeps retired keys, so a report from two rotations ago still resolves.
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        using var response = await http
            .GetAsync(new Uri(new Uri(origin), $"/api/v1/keys/{keyId}.pem"), cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            Console.Error.WriteLine(
                $"proofdrill: {origin} does not publish a key called '{keyId}' (HTTP " +
                $"{(int)response.StatusCode}). A report naming a key its own control plane no longer publishes " +
                "cannot be checked by anybody, which is worth knowing about a document somebody is relying on.");
            return CouldNotAttempt;
        }

        pem = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }
    else
    {
        Console.Error.WriteLine(
            "proofdrill: pass --public-key <file> or --control-plane <url> to check the counter-signature. " +
            "Without one of them this command can only say that a signature is present, which is not a check.");
        return CouldNotAttempt;
    }

    using var key = System.Security.Cryptography.ECDsa.Create();
    key.ImportFromPem(pem);

    if (!Signatures.VerifyCounterSignature(canonical, key, signature))
    {
        Console.Error.WriteLine(
            "proofdrill: THE COUNTER-SIGNATURE DOES NOT VERIFY. This report was altered after it was received, or " +
            "it was not signed by the key you supplied.");
        return Failed;
    }

    var receivedAt = envelope["receipt"]?["receivedAt"]?.GetValue<string>() ?? "an unstated time";
    var outcome = envelope["report"]?["outcome"]?.GetValue<string>() ?? "unknown";
    Console.WriteLine();
    Console.WriteLine($"  VERIFIED   received {receivedAt}, and unchanged since");
    Console.WriteLine($"  outcome    {outcome}");
    Console.WriteLine($"  agent      {envelope["agent"]?["id"]} version {envelope["agent"]?["version"]}");
    Console.WriteLine($"  key        {keyId ?? "unnamed"}");
    Console.WriteLine();
    return Passed;
}

async Task<int> DoctorAsync(CommandLine command, CancellationToken cancellationToken)
{
    var report = await DoctorRunner.RunAsync(
        StorageFrom(command),
        command.Integer("--pg-major"),
        command.Number("--rpo-window-hours"),
        command.Value("--work-dir") ?? DefaultWorkRoot(),
        cancellationToken).ConfigureAwait(false);

    if (command.Has("--json"))
    {
        Console.WriteLine(JsonSerializer.Serialize(report, ReportJson.Format));
    }
    else
    {
        Console.WriteLine();
        Console.WriteLine(report.Ready
            ? "  READY   the storage, the keys and this machine can run a drill"
            : "  NOT READY   see below. Nothing here says anything about whether the backup restores.");
        Console.WriteLine();

        foreach (var check in report.Checks)
        {
            Console.WriteLine($"  [{Mark(check.Outcome)}] {check.Key}");
            Console.WriteLine($"      {check.Detail}");
        }

        Console.WriteLine();
        Console.WriteLine("  NOT checked by the doctor");
        foreach (var item in report.NotAttempted)
        {
            Console.WriteLine($"      {item}");
        }

        Console.WriteLine();
    }

    return report.Ready ? Passed : CouldNotAttempt;
}

// The endpoint decides the addressing style. Amazon moved to virtual hosted
// buckets; almost everything else that speaks S3 — MinIO, R2, Spaces, Backblaze
// — is happiest with a path. Either can be forced, because a heuristic that
// cannot be overridden is a bug with a good excuse.
StorageOptions StorageFrom(CommandLine command)
{
    var endpoint = new Uri(command.Required("--s3-endpoint"));
    var amazon = endpoint.Host.EndsWith("amazonaws.com", StringComparison.OrdinalIgnoreCase);

    return new StorageOptions(
        Endpoint: endpoint,
        Bucket: command.Required("--s3-bucket"),
        Prefix: command.Value("--s3-prefix") ?? "",
        Pattern: command.Value("--s3-pattern") ?? "*",
        Region: command.Value("--s3-region") ?? "us-east-1",
        PathStyle: command.Has("--s3-path-style") || (!amazon && !command.Has("--s3-virtual-host")));
}

async Task<string> FetchAsync(StorageOptions storage, string workRoot, CancellationToken cancellationToken)
{
    var (accessKeyId, secretAccessKey) = ArtefactLocator.Credentials();

    using var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    var client = new S3Client(http, storage, accessKeyId, secretAccessKey);

    var listed = await client.ListAsync(storage.Prefix, 1000, cancellationToken).ConfigureAwait(false);
    var artefact = ArtefactLocator.Newest(listed, storage.Pattern)
        ?? throw new DrillCannotBeAttemptedException(
            $"nothing under '{storage.Prefix}' in '{storage.Bucket}' matches '{storage.Pattern}'. " +
            "Run `proofdrill doctor` with the same options: an empty listing and a key that may not list " +
            "look identical from here, and the doctor tells them apart.");

    var destination = Path.Combine(workRoot, "artefact.dump");
    Directory.CreateDirectory(workRoot);

    Console.Error.WriteLine($"proofdrill: fetching {artefact.Key} ({artefact.SizeBytes} bytes)");
    await client.GetAsync(artefact, destination, artefact.SizeBytes * 3, cancellationToken).ConfigureAwait(false);

    return destination;
}

async Task<int> DrillAsync(CommandLine command, CancellationToken cancellationToken)
{
    var workRoot = command.Value("--work-dir") ?? DefaultWorkRoot();

    // A local file or a bucket, and exactly one of them. Guessing between them
    // would mean silently drilling yesterday's download when today's fetch was
    // meant.
    var artefactPath = command.Value("--dump-file") is { } local
        ? local
        : await FetchAsync(StorageFrom(command), workRoot, cancellationToken).ConfigureAwait(false);

    var options = new DrillOptions(
        ArtefactPath: artefactPath,
        PostgresMajor: command.Integer("--pg-major"),
        DryRun: command.Has("--dry-run"),
        WorkRoot: workRoot,
        RpoWindowHours: command.Number("--rpo-window-hours"));

    var report = await DrillRunner.RunAsync(options, cancellationToken).ConfigureAwait(false);

    if (command.Has("--envelope") || command.Value("--report-to") is not null)
    {
        var envelope = ReportEnvelope.Sign(
            ReportEnvelope.Build(report, Identity(command)),
            AgentId(command),
            ReportEnvelope.Token());

        if (command.Has("--envelope"))
        {
            Console.WriteLine(envelope.ToJsonString(ReportJson.Format));
        }

        if (command.Value("--report-to") is { } endpoint)
        {
            await PostAsync(envelope, endpoint, cancellationToken).ConfigureAwait(false);
        }
    }
    else if (command.Has("--json"))
    {
        Console.WriteLine(report.ToJson());
    }
    else
    {
        Print(report);
    }

    return report.Outcome switch
    {
        Outcome.Passed => Passed,
        Outcome.Failed => Failed,
        _ => CouldNotAttempt,
    };
}

// The long-running mode: ask the control plane for work, do it, send the report,
// ask again.
//
// EVERYTHING HERE IS OUTBOUND. Nothing listens on this machine, no port is
// opened, and no rule has to be requested from whoever runs the firewall — which
// is the property that lets this product be installed in an afternoon rather
// than in a quarter. The control plane never connects to anything; it answers.
//
// A drill that could not be attempted is REPORTED, not swallowed. A narrow key
// or a missing artefact says nothing about the backup, but it says a great deal
// to the person who configured the target, and an agent that stayed silent would
// leave them looking at a queue that empties into nothing.
async Task<int> RunAsync(CommandLine command, CancellationToken cancellationToken)
{
    var origin = new Uri(command.Required("--control-plane"));
    var pollSeconds = Math.Clamp(command.Integer("--poll-seconds") ?? 60, 5, 3600);
    var workRoot = command.Value("--work-dir") ?? DefaultWorkRoot();
    var token = ReportEnvelope.Token();
    var agentId = RegisteredAgentId(command);
    var identity = new AgentIdentity(agentId, DrillRunner.AgentVersion(), Environment.MachineName);

    using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };

    // The keys that check what this agent is told. Fetched on first need and
    // again whenever the control plane signs with an id this process has not
    // seen, which is what a rotation looks like from inside somebody's
    // perimeter.
    using var keys = new PublishedKeys(http, origin);
    var controlPlane = new ControlPlane(http, origin, agentId, token, keys);

    Console.Error.WriteLine(
        $"proofdrill: asking {origin} for work every {pollSeconds}s. Nothing listens on this machine.");

    while (!cancellationToken.IsCancellationRequested)
    {
        AssignedJob? job;
        try
        {
            job = await controlPlane.ClaimAsync(identity, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is StorageException or HttpRequestException)
        {
            // Loud, and then it keeps going. A control plane that is briefly
            // unreachable is a Tuesday; an agent that exits on it is an agent
            // somebody has to notice and restart, which is the failure mode this
            // whole design exists to avoid.
            Console.Error.WriteLine($"proofdrill: {exception.Message}");
            job = null;
        }

        if (job is not null)
        {
            await RunOneAsync(controlPlane, identity, job, workRoot, cancellationToken).ConfigureAwait(false);
        }
        else if (command.Has("--once"))
        {
            Console.Error.WriteLine("proofdrill: nothing to do, and --once was asked for.");
            return Passed;
        }

        if (command.Has("--once") && job is not null)
        {
            return Passed;
        }

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(pollSeconds), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            break;
        }
    }

    Console.Error.WriteLine("proofdrill: stopped on request.");
    return Passed;
}

async Task RunOneAsync(
    ControlPlane controlPlane,
    AgentIdentity identity,
    AssignedJob job,
    string workRoot,
    CancellationToken cancellationToken)
{
    Console.Error.WriteLine($"proofdrill: drilling {job.TargetName} (job {job.Id})");

    var startedAt = DateTimeOffset.UtcNow;
    DrillReport report;

    try
    {
        var artefact = await FetchAsync(job.Storage, workRoot, cancellationToken).ConfigureAwait(false);

        report = await DrillRunner.RunAsync(
            new DrillOptions(
                ArtefactPath: artefact,
                PostgresMajor: job.PostgresMajor,
                DryRun: false,
                WorkRoot: workRoot,
                RpoWindowHours: job.RpoWindowHours),
            cancellationToken).ConfigureAwait(false);
    }
    catch (Exception exception) when (exception is DrillCannotBeAttemptedException or StorageException)
    {
        // §8.1, and the reason the third outcome exists at all: this is a
        // correction and never a verdict. It is sent rather than logged, because
        // the person who has to act on it is looking at a screen somewhere else.
        Console.Error.WriteLine($"proofdrill: could not attempt this drill. {exception.Message}");
        report = CouldNotAttemptReport(job, startedAt, exception.Message);
    }

    try
    {
        var envelope = ReportEnvelope.Sign(
            ReportEnvelope.Build(report, identity), identity.Id, ReportEnvelope.Token());

        await controlPlane.PostReportAsync(envelope, job.Id, cancellationToken).ConfigureAwait(false);
        Console.Error.WriteLine($"proofdrill: reported {report.Outcome} for {job.TargetName}.");
    }
    catch (Exception exception) when (exception is StorageException or HttpRequestException)
    {
        // The drill happened and its report did not arrive. Said plainly: the
        // job's lease will run out and the control plane will queue another,
        // which is the right outcome — nothing pretends this one counted.
        Console.Error.WriteLine($"proofdrill: {exception.Message}");
    }
}

/// <summary>
/// A report for a drill that never got as far as restoring anything. Every field
/// the protocol requires is present and none of them pretends: no measurements,
/// no row counts, and a level 1 check that says what stopped it in the agent's
/// own words.
/// </summary>
static DrillReport CouldNotAttemptReport(AssignedJob job, DateTimeOffset startedAt, string reason) => new(
    ReportVersion: DrillReport.CurrentVersion,
    Outcome: Outcome.CouldNotAttempt,
    AgentVersion: DrillRunner.AgentVersion(),
    PostgresMajor: null,
    StartedAt: startedAt,
    Artefact: new ArtefactFacts(
        FileName: job.Storage.Pattern,
        SizeBytes: 0,
        LastModified: DateTimeOffset.UnixEpoch,
        AgeHours: 0,
        DumpedFromMajor: null),
    Measurements: new Measurements(null, null),
    Level1: [new Check("artefact_present", Outcome.CouldNotAttempt, reason)],
    Level3: [],
    RowCounts: new Dictionary<string, long>(),
    Observations:
    [
        $"looked in bucket '{job.Storage.Bucket}' under '{job.Storage.Prefix}' for '{job.Storage.Pattern}' " +
        $"at {job.Storage.Endpoint}",
    ],
    NotAttempted:
    [
        "everything after the artefact: nothing was downloaded, nothing was restored and no assertion was evaluated.",
        "measured RPO and RTO: there is no artefact to measure the age of, and no restore to time.",
    ]);

// Page one is for the person who pays and cannot read SQL; the detail sits
// underneath. docs/03 §9.
void Print(DrillReport report)
{
    Console.WriteLine();
    Console.WriteLine($"  {report.Outcome.Replace('_', ' ').ToUpperInvariant()}   {report.Artefact.FileName}");
    Console.WriteLine();
    Console.WriteLine($"  measured RPO   {report.Measurements.MeasuredRpoHours:0.0} h  (age of the backup)");
    Console.WriteLine(report.Measurements.MeasuredRtoSeconds is { } rto
        ? $"  measured RTO   {rto:0.0} s  (real time to restore it)"
        : "  measured RTO   not measured");
    Console.WriteLine($"  PostgreSQL     {report.PostgresMajor}");
    Console.WriteLine();

    Console.WriteLine("  level 1 — did the restore happen?");
    foreach (var check in report.Level1)
    {
        Console.WriteLine($"  [{Mark(check.Outcome)}] {check.Key}");
        Console.WriteLine($"      {check.Detail}");
    }

    if (report.Level3.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("  level 3 — do the guarantees still hold?");
        foreach (var check in report.Level3)
        {
            Console.WriteLine($"  [{Mark(check.Outcome)}] {check.Key}");
            Console.WriteLine($"      {check.Detail}");
        }
    }

    if (report.RowCounts.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("  rows restored");
        foreach (var (table, count) in report.RowCounts)
        {
            Console.WriteLine($"      {table}: {count}");
        }
    }

    if (report.Observations.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("  observed");
        foreach (var observation in report.Observations)
        {
            Console.WriteLine($"      {observation}");
        }
    }

    // Printed every time, never folded away. What was not checked is the part a
    // reader will otherwise assume was checked and passed.
    Console.WriteLine();
    Console.WriteLine("  NOT checked by this run");
    foreach (var item in report.NotAttempted)
    {
        Console.WriteLine($"      {item}");
    }

    Console.WriteLine();
}

static AgentIdentity Identity(CommandLine command) =>
    new(AgentId(command), DrillRunner.AgentVersion(), Environment.MachineName);

// The machine name is a fallback for a drill run by hand with nowhere to report
// — it identifies the report on the terminal and nothing more.
static string AgentId(CommandLine command) =>
    command.Value("--agent-id")
    ?? Environment.GetEnvironmentVariable("PROOFDRILL_AGENT_ID")
    ?? Environment.MachineName;

/// <summary>
/// The id the control plane assigned at registration, and no fallback.
/// <para>
/// A machine name is not a registered agent: the control plane resolves an
/// organisation from this id, and one that is not a registered id is refused with
/// the same silence as a forged signature — deliberately, because an agent id
/// must tell a stranger nothing. Refusing here, by name, is the difference
/// between a message somebody can act on and a poll loop that says "rejected"
/// for ever.
/// </para>
/// </summary>
static string RegisteredAgentId(CommandLine command) =>
    command.Value("--agent-id")
    ?? Environment.GetEnvironmentVariable("PROOFDRILL_AGENT_ID")
    ?? throw new UsageException(
        "PROOFDRILL_AGENT_ID is not set. `run` needs the agent id the control plane assigned when you " +
        "registered this agent — it is in the docker run line that page gave you, beside the token.");

async Task PostAsync(System.Text.Json.Nodes.JsonObject envelope, string endpoint, CancellationToken cancellationToken)
{
    using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
    using var body = new StringContent(envelope.ToJsonString(), System.Text.Encoding.UTF8, "application/json");
    using var response = await http.PostAsync(new Uri(endpoint), body, cancellationToken).ConfigureAwait(false);

    var answer = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

    if (!response.IsSuccessStatusCode)
    {
        // Never silently: a drill whose report did not arrive is a drill that did
        // not happen as far as anybody reading the history is concerned, and the
        // clock must not move for it.
        throw new DrillCannotBeAttemptedException(
            $"the report was not accepted by {endpoint}: HTTP {(int)response.StatusCode}. {answer.Trim()}");
    }

    Console.WriteLine(answer);
}

static string Mark(string outcome) => outcome switch
{
    Outcome.Passed => "pass",
    Outcome.Failed => "FAIL",
    _ => " -- ",
};

static string Majors()
{
    var majors = PostgresBinaries.AvailableMajors();
    return majors.Count == 0 ? "none (this is not the agent image)" : string.Join(", ", majors);
}

static string DefaultWorkRoot() =>
    Directory.Exists("/work") ? "/work" : Path.Combine(Path.GetTempPath(), "proofdrill");

static void Help()
{
    Console.WriteLine("""

        proofdrill — prove a PostgreSQL backup restores, and that the restored
                     database still enforces what the original enforced.

          proofdrill doctor --s3-endpoint <url> --s3-bucket <name> [options]
          proofdrill drill --dump-file <path> [options]
          proofdrill drill --s3-endpoint <url> --s3-bucket <name> [options]
          proofdrill run --control-plane <url> [options]
          proofdrill verify --report <file> [--public-key <file> | --control-plane <url>]
          proofdrill version

        doctor reaches the storage, finds the newest artefact, reads its age and
        size, and checks the disk. It restores nothing and DOWNLOADS nothing.

        run keeps asking your control plane for work and does what it is given.
        Everything is outbound: nothing listens on this machine, no port is
        opened, and no firewall rule is needed. The storage keys stay here.
        Every answer it gets is counter-signed, and one that does not verify
        against the control plane's published key is refused rather than obeyed.

        verify checks a report you were handed. The counter-signature is the one
        a third party checks, and it needs the public key of whichever key the
        report names: pass the file, or an origin to fetch it from. The same
        check is three lines of openssl — §6 of the published protocol — because
        an auditor who has to install our tool to check our attestation has been
        given an attestation about an attestation.

        verify options
          --report <file>             the envelope, as downloaded
          --public-key <file>         the key it names, in PEM
          --control-plane <url>       fetch that key from /api/v1/keys instead
          --agent                     check the agent's own signature instead
          --canonical-only            write the signed bytes to stdout and stop

        run options
          --control-plane <url>       the origin you signed up at
          --poll-seconds <n>          how often to ask (default 60)
          --once                      take at most one job, then exit
          --work-dir <path>           where the throwaway cluster lives (default /work)

        PROOFDRILL_TOKEN and PROOFDRILL_AGENT_ID come from the registration page,
        in the docker run line it shows once.

        drill options
          --dump-file <path>          a custom-format archive, as written by pg_dump -Fc
          --pg-major <n>              force a major; the default is the one the archive records
          --rpo-window-hours <n>      how old the backup is allowed to be, in hours
          --work-dir <path>           where the throwaway cluster lives (default /work)
          --dry-run                   read the archive, restore nothing, and say what was skipped
          --json                      print the report as JSON instead of prose

        storage options, for doctor and for a drill without --dump-file
          --s3-endpoint <url>         https://s3.eu-central-1.amazonaws.com, or your own
          --s3-bucket <name>
          --s3-prefix <path>          where the backups live inside the bucket
          --s3-pattern <glob>         which files are backups, e.g. "db-*.dump" (default *)
          --s3-region <name>          default us-east-1
          --s3-path-style             force bucket-in-the-path addressing
          --s3-virtual-host           force bucket-in-the-hostname addressing

        Credentials come from PROOFDRILL_S3_ACCESS_KEY_ID and
        PROOFDRILL_S3_SECRET_ACCESS_KEY and are never accepted as arguments: a
        command line is readable by every process on the machine.

        exit codes
          0   passed
          1   attempted, and the backup did not hold
          2   could not be attempted: a correction, not a verdict
          64  the command line was wrong
          70  the agent itself broke, which says nothing about the backup

        This build restores and runs level 1. Levels 2 and 3 are not implemented,
        and every run says so rather than leaving it to be assumed.

        """);
}
