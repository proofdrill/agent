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
            return Verify(command);

        // Named rather than hidden. Somebody reading the README will type this,
        // and "unknown subcommand" would suggest they are misremembering rather
        // than that we have not written it yet.
        case "run":
            await Console.Error.WriteLineAsync(
                $"proofdrill: `{command.Command}` does not exist yet. This build has `drill` and `version` only.")
                .ConfigureAwait(false);
            return UsageError;

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
int Verify(CommandLine command)
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

    if (command.Value("--public-key") is not { } keyPath)
    {
        Console.Error.WriteLine(
            "proofdrill: pass --public-key to check the counter-signature. Without it this command can only say " +
            "that a signature is present, which is not a check.");
        return CouldNotAttempt;
    }

    using var key = System.Security.Cryptography.ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(keyPath));

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

async Task<string> FetchAsync(CommandLine command, string workRoot, CancellationToken cancellationToken)
{
    var storage = StorageFrom(command);
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
        : await FetchAsync(command, workRoot, cancellationToken).ConfigureAwait(false);

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

// Provisional until registration exists: the control plane will assign this at
// enrolment, and the token will be bound to it. Written down as provisional so
// nobody builds on it by mistake.
static string AgentId(CommandLine command) =>
    command.Value("--agent-id")
    ?? Environment.GetEnvironmentVariable("PROOFDRILL_AGENT_ID")
    ?? Environment.MachineName;

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
          proofdrill version

        doctor reaches the storage, finds the newest artefact, reads its age and
        size, and checks the disk. It restores nothing and DOWNLOADS nothing.

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
