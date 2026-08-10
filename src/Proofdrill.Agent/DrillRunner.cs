using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Proofdrill.Agent;

internal sealed record DrillOptions(
    string ArtefactPath,
    int? PostgresMajor,
    bool DryRun,
    string WorkRoot,
    double? RpoWindowHours);

/// <summary>
/// One drill against one artefact, on this machine, with no network and no
/// control plane. This is the whole product reduced to the part that can be run
/// from a shell before anybody has an account.
/// </summary>
internal static partial class DrillRunner
{
    private const string RestoredDatabase = "restored";

    /// <summary>
    /// Free disk demanded before anything is downloaded or expanded. The
    /// multiplier is a floor and not a measurement — the compressed artefact
    /// becomes a data directory plus rebuilt indexes — and it is checked BEFORE
    /// the work rather than during it, because filling somebody else's disk
    /// halfway through a restore is the one failure this product cannot afford.
    /// </summary>
    private const int DiskMultiplier = 3;

    public static async Task<DrillReport> RunAsync(DrillOptions options, CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var checks = new List<Check>();
        var observations = new List<string>();
        var notAttempted = new List<string>();
        var rowCounts = new Dictionary<string, long>(StringComparer.Ordinal);

        var file = new FileInfo(options.ArtefactPath);
        if (!file.Exists)
        {
            throw new DrillCannotBeAttemptedException($"no artefact at '{options.ArtefactPath}'");
        }

        if (file.Length == 0)
        {
            // An empty file is the shape of the failure this product exists to
            // catch, so it is named rather than left to pg_restore to describe.
            throw new DrillCannotBeAttemptedException(
                $"the artefact '{file.Name}' is zero bytes. A backup that is empty and well formed is " +
                "the failure this product was built for, but an empty file cannot be drilled.");
        }

        var lastModified = new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero);
        var ageHours = (startedAt - lastModified).TotalHours;

        var available = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(options.WorkRoot)) ?? "/").AvailableFreeSpace;
        var required = file.Length * DiskMultiplier;
        if (available < required)
        {
            throw new DrillCannotBeAttemptedException(
                $"not enough free disk: the artefact is {Bytes(file.Length)}, this drill wants at least " +
                $"{Bytes(required)} free under '{options.WorkRoot}', and {Bytes(available)} is available.");
        }

        checks.Add(new Check("artefact_present", Outcome.Passed,
            $"{file.Name}, {Bytes(file.Length)}, written {ageHours:0.0} h ago"));

        if (options.RpoWindowHours is { } window)
        {
            checks.Add(ageHours <= window
                ? new Check("artefact_within_rpo_window", Outcome.Passed,
                    $"{ageHours:0.0} h old, window is {window:0.0} h")
                : new Check("artefact_within_rpo_window", Outcome.Failed,
                    $"{ageHours:0.0} h old, which is outside the declared window of {window:0.0} h"));
        }
        else
        {
            notAttempted.Add("artefact_within_rpo_window: no window was declared, so the age is measured and not judged");
        }

        // The version gate happens BEFORE the restore, never after. pg_restore
        // records the server that wrote the archive in its own table of contents,
        // so this costs nothing and it is the difference between a clear refusal
        // and a restore that half works.
        var probe = PostgresBinaries.For(options.PostgresMajor ?? PostgresBinaries.AvailableMajors().LastOrDefault())
            ?? throw new DrillCannotBeAttemptedException(
                "this image carries no PostgreSQL server binaries at all, so no drill is possible here");

        var sourceMajor = await ReadSourceMajorAsync(probe, options.ArtefactPath, cancellationToken)
            .ConfigureAwait(false);

        var major = options.PostgresMajor ?? sourceMajor;
        if (major is null)
        {
            throw new DrillCannotBeAttemptedException(
                "the artefact does not record which PostgreSQL version wrote it, and no --pg-major was given");
        }

        var binaries = PostgresBinaries.For(major.Value)
            ?? throw new DrillCannotBeAttemptedException(
                $"the artefact was written by PostgreSQL {major}, and this image carries " +
                $"[{string.Join(", ", PostgresBinaries.AvailableMajors())}]. Restoring with a different major is " +
                "not a restore, so this drill stops here rather than producing a report nobody should trust.");

        var artefactFacts = new ArtefactFacts(file.Name, file.Length, lastModified, Math.Round(ageHours, 2), sourceMajor);

        var contents = await ArtefactInspector.ReadAsync(binaries, options.ArtefactPath, cancellationToken)
            .ConfigureAwait(false);

        observations.Add(
            $"the artefact declares {contents.Tables.Count} table(s), {contents.Declared.Policies.Count} policy(ies), " +
            $"{contents.Declared.RowLevelSecurity.Count} row level security statement(s) and " +
            $"{contents.Declared.Grants.Count} grant(s)");
        if (contents.ReferencedRoles.Count > 0)
        {
            observations.Add($"the artefact references role(s): {string.Join(", ", contents.ReferencedRoles)}");
        }

        if (options.DryRun)
        {
            // An honest dry run says what it did not do. A dry run that quietly
            // performs a subset teaches people to distrust the flag exactly when
            // they are being careful.
            notAttempted.Add("restore: --dry-run was given, so no cluster was created and nothing was restored");
            notAttempted.Add("level 1 assertions: they require a restored database");
            notAttempted.Add("level 3 assertions: not implemented yet");

            return new DrillReport(
                DrillReport.CurrentVersion, Outcome.CouldNotAttempt, AgentVersion(), major,
                startedAt, artefactFacts, new Measurements(Math.Round(ageHours, 2), null),
                checks, [], rowCounts, observations, notAttempted);
        }

        Directory.CreateDirectory(options.WorkRoot);
        await using var cluster = new ThrowawayCluster(binaries, options.WorkRoot);
        await cluster.CreateAsync(cancellationToken).ConfigureAwait(false);
        await cluster.StartAsync(cancellationToken).ConfigureAwait(false);

        var created = await cluster.QueryAsync("postgres", $"CREATE DATABASE {RestoredDatabase}", cancellationToken)
            .ConfigureAwait(false);
        if (!created.Succeeded)
        {
            throw new DrillCannotBeAttemptedException(created.Describe("creating the target database"));
        }

        // Every artefact names at least its owner, and a per-database pg_dump
        // carries no roles at all — so a restore into a fresh cluster fails on
        // ownership and grants for EVERY backup ever taken this way. Reporting
        // that as a failed drill would make the product cry wolf on its first
        // contact with every customer.
        //
        // So the missing roles are created here, empty, and the report says which
        // ones had to be invented. That makes the restore's exit code a signal
        // about the DATA again, and it moves the authorization question to where
        // it belongs: a correction, with an instruction, rather than a verdict.
        var existingRoles = (await cluster.QueryAsync("postgres",
                "SELECT rolname FROM pg_roles", cancellationToken).ConfigureAwait(false))
            .StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var invented = contents.ReferencedRoles.Except(existingRoles, StringComparer.Ordinal).ToList();
        foreach (var role in invented)
        {
            var quoted = role.Replace("\"", "\"\"", StringComparison.Ordinal);
            var made = await cluster.QueryAsync("postgres", $"CREATE ROLE \"{quoted}\" NOLOGIN", cancellationToken)
                .ConfigureAwait(false);
            if (!made.Succeeded)
            {
                throw new DrillCannotBeAttemptedException(made.Describe($"creating the placeholder role '{role}'"));
            }
        }

        var clock = Stopwatch.StartNew();
        var restore = await cluster
            .RestoreAsync(options.ArtefactPath, RestoredDatabase, cancellationToken, TimeSpan.FromHours(6))
            .ConfigureAwait(false);
        clock.Stop();

        checks.Add(restore.Succeeded
            ? new Check("restore_exit_code", Outcome.Passed, "pg_restore exited 0")
            : new Check("restore_exit_code", Outcome.Failed,
                $"pg_restore exited {restore.ExitCode}. " + FirstErrors(restore.StandardError)));

        var restoredTables = (await cluster.QueryAsync(RestoredDatabase,
                """
                SELECT n.nspname || '.' || c.relname
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                ORDER BY 1
                """, cancellationToken).ConfigureAwait(false))
            .StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var missingTables = contents.Tables.Except(restoredTables, StringComparer.Ordinal).ToList();
        checks.Add(missingTables.Count == 0
            ? new Check("expected_tables_present", Outcome.Passed,
                $"all {contents.Tables.Count} table(s) named in the artefact are in the restored database")
            : new Check("expected_tables_present", Outcome.Failed,
                $"missing after restore: {string.Join(", ", missingTables)}"));

        // Exact counts, never pg_stat estimates: a report that says "about" is not
        // evidence, and n_live_tup is a statistic that can be stale or zero.
        var counts = await cluster.QueryAsync(RestoredDatabase,
            """
            SELECT table_schema || '.' || table_name,
                   (xpath('/row/c/text()', query_to_xml(
                       format('SELECT count(*) AS c FROM %I.%I', table_schema, table_name),
                       false, true, '')))[1]::text::bigint
            FROM information_schema.tables
            WHERE table_type = 'BASE TABLE'
              AND table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY 1
            """, cancellationToken).ConfigureAwait(false);

        foreach (var row in ThrowawayCluster.Rows(counts))
        {
            if (row.Length == 2 && long.TryParse(row[1], out var value))
            {
                rowCounts[row[0]] = value;
            }
        }

        notAttempted.Add(
            "row_counts_within_tolerance: a tolerance needs a previous drill to compare against. " +
            $"The {rowCounts.Count} count(s) in this report are what the next one will be measured against.");

        // The founding failure of this product, and the one check that catches it
        // without any history to compare against: an archive that is well formed,
        // restores with exit code 0, and contains no rows at all. `pg_dump` writes
        // exactly that against a FORCE ROW LEVEL SECURITY database when it is run
        // with --enable-row-security by a role that has no read-all policy.
        if (rowCounts.Count > 0 && rowCounts.Values.All(count => count == 0))
        {
            checks.Add(new Check("restored_database_not_empty", Outcome.Failed,
                $"the restore succeeded and all {rowCounts.Count} table(s) are empty. An archive that is valid and " +
                "empty is what pg_dump produces against a forced row level security database when the role taking " +
                "the backup cannot read the rows — it exits zero and it carries nothing."));
        }
        else
        {
            checks.Add(new Check("restored_database_not_empty", Outcome.Passed,
                $"{rowCounts.Values.Sum()} row(s) across {rowCounts.Count} table(s)"));
        }

        // Spike 0's finding, reported as what it is. Not a failed drill: an
        // artefact that cannot answer the question, with the instruction attached.
        if (invented.Count > 0)
        {
            observations.Add(
                $"the artefact does not carry the cluster globals, so {invented.Count} role(s) were created empty to " +
                $"let the restore complete: {string.Join(", ", invented)}");

            notAttempted.Add(
                "level 3, role attributes: roles are cluster-wide and a per-database pg_dump does not contain them, " +
                "so whether any role holds BYPASSRLS cannot be tested. Add the pg_dumpall --globals-only artefact " +
                "to this target and it becomes testable. This is a correction, not a verdict.");

            notAttempted.Add(
                "level 3, application role isolation: the placeholder roles have no memberships or attributes, so " +
                "what the real application role could read cannot be established from this artefact alone.");
        }

        // ---- level 3: do the guarantees still hold? -------------------------
        //
        // The restored database is dumped with the same pg_dump that wrote the
        // artefact, so both sides of the comparison go through one normalisation
        // and a difference means a difference. See SecurityDdl for why reading
        // pg_policies instead would report every policy as changed.
        var level3 = new List<Check>();

        var restoredDdl = await Processes.RunAsync(
            binaries.PgDump,
            ["--section", "pre-data", "--section", "post-data", "--file", "-", "--dbname", RestoredDatabase],
            cluster.Environment(),
            TimeSpan.FromMinutes(10),
            cancellationToken).ConfigureAwait(false);

        if (!restoredDdl.Succeeded)
        {
            throw new DrillCannotBeAttemptedException(
                restoredDdl.Describe("dumping the restored database to compare its guarantees"));
        }

        var restored = SecurityDdl.Extract(restoredDdl.StandardOutput);

        Compare(level3, "rls_enabled_and_forced_preserved",
            contents.Declared.RowLevelSecurity, restored.RowLevelSecurity,
            "row level security statement");
        Compare(level3, "policies_identical",
            contents.Declared.Policies, restored.Policies, "policy");
        Compare(level3, "grants_identical",
            contents.Declared.Grants, restored.Grants, "grant");

        // Behaviour, not flags. Rule 7 of this repository: the agent is superuser
        // of its own cluster and a superuser bypasses row level security, so
        // "I could read the table" proves nothing. The owner is the interesting
        // role, because FORCE ROW LEVEL SECURITY exists precisely so that the
        // owner is not exempt.
        var forced = ThrowawayCluster.Rows(await cluster.QueryAsync(RestoredDatabase,
            """
            SELECT n.nspname || '.' || c.relname, pg_get_userbyid(c.relowner)
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r' AND c.relrowsecurity AND c.relforcerowsecurity
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY 1
            """, cancellationToken).ConfigureAwait(false)).Where(row => row.Length == 2).ToList();

        if (forced.Count == 0)
        {
            notAttempted.Add(
                "level 3, enforcement: the restored database has no table with row level security FORCED, so there " +
                "is no owner-level restriction to demonstrate. Enabled without forced leaves the owner exempt.");
        }
        else
        {
            const int Ceiling = 25;
            var probed = forced.Take(Ceiling).ToList();
            if (forced.Count > probed.Count)
            {
                // Never a silent cap: a truncated check that reads as a complete
                // one is how a report starts overstating what it covered.
                observations.Add(
                    $"enforcement was probed on {probed.Count} of {forced.Count} forced tables (per run ceiling)");
            }

            var restricting = new List<string>();
            var unrestricted = new List<string>();

            foreach (var row in probed)
            {
                var owner = row[1].Replace("\"", "\"\"", StringComparison.Ordinal);
                var asOwner = await cluster.QueryAsync(RestoredDatabase,
                    $"SET ROLE \"{owner}\"; SELECT count(*) FROM {row[0]}", cancellationToken).ConfigureAwait(false);

                if (!asOwner.Succeeded || !long.TryParse(asOwner.StandardOutput.Trim(), out var visible))
                {
                    unrestricted.Add($"{row[0]} (could not be read as {row[1]})");
                    continue;
                }

                var total = rowCounts.GetValueOrDefault(row[0], 0);
                (visible < total ? restricting : unrestricted).Add(
                    $"{row[0]}: {visible} of {total} rows visible to {row[1]}");
            }

            if (unrestricted.Count == 0)
            {
                level3.Add(new Check("row_level_security_actually_restricts", Outcome.Passed,
                    $"with no tenant context set, the owner sees fewer rows than the whole table on all " +
                    $"{restricting.Count} forced table(s): {string.Join("; ", restricting)}"));
            }
            else
            {
                // Deliberately not a verdict. A policy that is legitimately
                // permissive produces exactly this reading, and check
                // rls_enabled_and_forced_preserved above already catches the case
                // where the guarantee did not survive the restore. Crying wolf
                // here would cost more than the extra certainty is worth.
                level3.Add(new Check("row_level_security_actually_restricts", Outcome.CouldNotAttempt,
                    $"the owner still sees every row of {string.Join("; ", unrestricted)}. That is what a policy " +
                    "which permits everything looks like, and it is also what a lost guarantee looks like; the two " +
                    "are told apart by a customer SQL assertion, which this build does not support."));
            }
        }

        notAttempted.Add(
            "level 3, role attributes: whether any role holds BYPASSRLS cannot be read from a per-database artefact, " +
            "because role attributes live in the cluster globals.");
        notAttempted.Add("level 3, customer SQL assertions: not implemented yet");
        notAttempted.Add("level 2 entirely: extensions, sequences, constraints, foreign keys, functions and triggers");

        // A level 3 failure is a failed drill. That is the whole product: a backup
        // that restores with every row in place and its guarantees missing is not
        // a successful restore. A could-not-attempt never lowers the verdict — it
        // is a correction, and corrections do not decide anything.
        var outcome = checks.Concat(level3).Any(c => c.Outcome == Outcome.Failed)
            ? Outcome.Failed
            : Outcome.Passed;

        return new DrillReport(
            DrillReport.CurrentVersion, outcome, AgentVersion(), major, startedAt, artefactFacts,
            new Measurements(Math.Round(ageHours, 2), Math.Round(clock.Elapsed.TotalSeconds, 3)),
            checks, level3, rowCounts, observations, notAttempted);
    }

    /// <summary>
    /// One guarantee compared in both directions. A restored database that
    /// <em>gained</em> a policy is as much a finding as one that lost it: either
    /// way it is not the database the artefact describes.
    /// </summary>
    private static void Compare(
        List<Check> checks,
        string key,
        IReadOnlySet<string> declared,
        IReadOnlySet<string> restored,
        string noun)
    {
        if (declared.Count == 0)
        {
            checks.Add(new Check(key, Outcome.CouldNotAttempt,
                $"the artefact declares no {noun}, so there is nothing to preserve. " +
                (restored.Count == 0 ? "" : $"The restored database has {restored.Count}, which it should not.")));
            return;
        }

        var (lost, gained) = SecurityDdl.Compare(declared, restored);

        if (lost.Count == 0 && gained.Count == 0)
        {
            checks.Add(new Check(key, Outcome.Passed,
                $"all {declared.Count} {noun}(s) the artefact declares are present in the restored database, identical"));
            return;
        }

        var detail = new List<string>();
        if (lost.Count > 0)
        {
            detail.Add($"lost: {string.Join(" | ", lost)}");
        }

        if (gained.Count > 0)
        {
            detail.Add($"appeared: {string.Join(" | ", gained)}");
        }

        checks.Add(new Check(key, Outcome.Failed, string.Join("; ", detail)));
    }

    private static async Task<int?> ReadSourceMajorAsync(
        PostgresBinaries binaries,
        string artefact,
        CancellationToken cancellationToken)
    {
        var toc = await Processes.RunAsync(
            binaries.PgRestore,
            ["--list", artefact],
            timeout: TimeSpan.FromMinutes(2),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if (!toc.Succeeded)
        {
            return null;
        }

        var match = DumpedFrom().Match(toc.StandardOutput);
        return match.Success && int.TryParse(match.Groups["major"].Value, out var major) ? major : null;
    }

    /// <summary>The first few lines of a failure, so the message names a cause rather than a page.</summary>
    private static string FirstErrors(string standardError)
    {
        var lines = standardError
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => line.Contains("error", StringComparison.OrdinalIgnoreCase))
            .Take(3)
            .ToList();

        return lines.Count == 0 ? "" : string.Join(" | ", lines);
    }

    private static string Bytes(long value) => value switch
    {
        >= 1L << 30 => $"{value / (double)(1L << 30):0.0} GiB",
        >= 1L << 20 => $"{value / (double)(1L << 20):0.0} MiB",
        >= 1L << 10 => $"{value / (double)(1L << 10):0.0} KiB",
        _ => $"{value} B",
    };

    public static string AgentVersion() =>
        typeof(DrillRunner).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    [GeneratedRegex(@"Dumped from database version:\s*(?<major>\d+)")]
    private static partial Regex DumpedFrom();
}
