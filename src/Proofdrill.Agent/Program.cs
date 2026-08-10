using System.Runtime.InteropServices;
using Proofdrill.Agent;

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

        // Named rather than hidden. Somebody reading the README will type these,
        // and "unknown subcommand" would suggest they are misremembering rather
        // than that we have not written them yet.
        case "doctor":
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

async Task<int> DrillAsync(CommandLine command, CancellationToken cancellationToken)
{
    var options = new DrillOptions(
        ArtefactPath: command.Required("--dump-file"),
        PostgresMajor: command.Integer("--pg-major"),
        DryRun: command.Has("--dry-run"),
        WorkRoot: command.Value("--work-dir") ?? DefaultWorkRoot(),
        RpoWindowHours: command.Number("--rpo-window-hours"));

    var report = await DrillRunner.RunAsync(options, cancellationToken).ConfigureAwait(false);

    if (command.Has("--json"))
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

          proofdrill drill --dump-file <path> [options]
          proofdrill version

        drill options
          --dump-file <path>          a custom-format archive, as written by pg_dump -Fc
          --pg-major <n>              force a major; the default is the one the archive records
          --rpo-window-hours <n>      how old the backup is allowed to be, in hours
          --work-dir <path>           where the throwaway cluster lives (default /work)
          --dry-run                   read the archive, restore nothing, and say what was skipped
          --json                      print the report as JSON instead of prose

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
