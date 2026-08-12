using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Proofdrill.Agent;

/// <summary>
/// The second artefact — <c>pg_dumpall --globals-only</c> — as it was found. The
/// roles are cluster-wide, so they are never inside a per-database archive, and
/// without them level 3's central question has no role to ask about.
/// </summary>
internal sealed record GlobalsArtefact(string Path, string Name, long SizeBytes, DateTimeOffset LastModified);

internal sealed record DrillOptions(
    string ArtefactPath,
    int? PostgresMajor,
    bool DryRun,
    string WorkRoot,
    double? RpoWindowHours,
    AssertionPack? Assertions = null,
    GlobalsArtefact? Globals = null,
    string? GlobalsNote = null);

/// <summary>
/// What a globals artefact contributed, once it had been read and applied. Null
/// everywhere else means the same thing it has always meant: the roles in this
/// cluster are placeholders this agent invented so the restore could finish.
/// </summary>
internal sealed record AppliedGlobals(IReadOnlyList<DeclaredRole> Roles, IReadOnlyList<string> Failures);

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

    /// <summary>Used only when the artefact does not record one of its own.</summary>
    private const string DefaultEncoding = "UTF8";

    /// <summary>
    /// How many column-owned sequences one drill measures. A ceiling rather than
    /// a scan, because each one costs a <c>max()</c> over its own table; going
    /// over it is reported and never silent.
    /// </summary>
    private const int SequenceCeiling = 25;

    /// <summary>
    /// Every sequence a column owns, the next value it will hand out, and the
    /// largest value already in that column.
    /// <para>
    /// <c>pg_depend</c> rather than a name convention: <c>'a'</c> is the
    /// dependency a <c>serial</c> column creates and <c>'i'</c> the one an
    /// identity column creates, and neither can be found by looking for a
    /// sequence called <c>t_id_seq</c>. Sequences that count downwards are left
    /// out — <c>max()</c> is the wrong question for them — and the total says how
    /// many there were.
    /// </para>
    /// </summary>
    private static readonly string SequenceProbe =
        $"""
        WITH owned AS (
            SELECT format('%I.%I', n.nspname, c.relname)   AS sequence_name,
                   format('%I.%I', tn.nspname, t.relname)  AS table_name,
                   a.attname                               AS column_name,
                   count(*) OVER ()                        AS total
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_depend d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid
                            AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')
            JOIN pg_class t ON t.oid = d.refobjid
            JOIN pg_namespace tn ON tn.oid = t.relnamespace
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.refobjsubid
            JOIN pg_sequences s ON s.schemaname = n.nspname AND s.sequencename = c.relname
            WHERE c.relkind = 'S' AND s.increment_by > 0
        )
        SELECT sequence_name, table_name, column_name, total,
               (xpath('/row/c/text()', query_to_xml(
                   format('SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END AS c FROM %s',
                          sequence_name), false, true, '')))[1]::text::bigint,
               (xpath('/row/c/text()', query_to_xml(
                   format('SELECT max(%I) AS c FROM %s', column_name, table_name),
                   false, true, '')))[1]::text::bigint
        FROM (SELECT * FROM owned ORDER BY sequence_name LIMIT {SequenceCeiling}) probed
        """;

    public static async Task<DrillReport> RunAsync(DrillOptions options, CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var checks = new List<Check>();
        var observations = new List<string>();
        var notAttempted = new List<string>();
        var rowCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        var pack = options.Assertions ?? AssertionPack.Empty;

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
            notAttempted.Add(
                "every assertion after the artefact itself: levels 1, 2 and 3 all ask their questions of a restored " +
                "database, and this run restored nothing");

            if (!pack.IsEmpty)
            {
                notAttempted.Add(
                    $"the {pack.Assertions.Count} assertion(s) in the pack: they were read and checked for shape, " +
                    "and a dry run has no database to ask them of");
            }

            if (options.Globals is { } skipped)
            {
                notAttempted.Add(
                    $"the cluster globals in '{skipped.Name}': there is no cluster to put the roles into, so " +
                    "whether any of them is exempt from a policy that names it was not asked");
            }

            return new DrillReport(
                DrillReport.CurrentVersion, Outcome.CouldNotAttempt, AgentVersion(), major,
                startedAt, artefactFacts, new Measurements(Math.Round(ageHours, 2), null),
                checks, [], [], rowCounts, observations, notAttempted);
        }

        Directory.CreateDirectory(options.WorkRoot);
        await using var cluster = new ThrowawayCluster(binaries, options.WorkRoot);
        await cluster.CreateAsync(ClusterEncoding(contents.Shape.Encoding, observations), cancellationToken)
            .ConfigureAwait(false);
        await cluster.StartAsync(cancellationToken).ConfigureAwait(false);

        // Before the database and before the restore. The roles the artefact's
        // objects belong to have to exist for ownership and grants to land at all,
        // and whether they are the customer's own roles or empty placeholders is
        // the difference between level 3 answering its central question and
        // reporting that it cannot.
        var globals = await ApplyGlobalsAsync(
                cluster, options.Globals, artefactFacts, observations, notAttempted, cancellationToken)
            .ConfigureAwait(false);

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
        if (invented.Count > 0 && globals is null)
        {
            observations.Add(
                $"the artefact does not carry the cluster globals, so {invented.Count} role(s) were created empty to " +
                $"let the restore complete: {string.Join(", ", invented)}");

            notAttempted.Add(
                "level 3, role attributes: roles are cluster-wide and a per-database pg_dump does not contain them, " +
                "so whether any role holds BYPASSRLS cannot be tested. " +
                (options.GlobalsNote
                 ?? "Add the pg_dumpall --globals-only artefact to this target and it becomes testable.") +
                " This is a correction, not a verdict.");

            notAttempted.Add(
                "level 3, application role isolation: the placeholder roles have no memberships or attributes, so " +
                "what the real application role could read cannot be established from this artefact alone." +
                (pack.Assertions.Any(assertion => assertion.Role is not null)
                    // Said whenever an assertion names a role, because the pass it
                    // produces is the exact thing a reader will over-read. It
                    // demonstrates what the restored policies do to a role of that
                    // name — not that the role in production is only that.
                    ? " An assertion below names a role, and it ran against one of those placeholders: it shows " +
                      "what the restored database's policies do to a role of that name, not what that role holds " +
                      "in production."
                    : ""));
        }

        // The restored database's own DDL, written by the same pg_dump that wrote
        // the artefact, so both sides of every comparison below go through one
        // normalisation and a difference means a difference. See SecurityDdl for
        // why reading pg_policies instead would report every policy as changed.
        var restoredDdl = await Processes.RunAsync(
            binaries.PgDump,
            ["--section", "pre-data", "--section", "post-data", "--file", "-", "--dbname", RestoredDatabase],
            cluster.Environment(),
            TimeSpan.FromMinutes(10),
            cancellationToken).ConfigureAwait(false);

        if (!restoredDdl.Succeeded)
        {
            throw new DrillCannotBeAttemptedException(
                restoredDdl.Describe("dumping the restored database to compare it against the artefact"));
        }

        // ---- level 2: is it still THAT database? ----------------------------
        //
        // pg_restore exiting non-zero already says that something did not come
        // back; these say WHAT, which is the difference between a report a person
        // can act on and a number they have to take to somebody else. And two of
        // them see failures the exit code cannot: a sequence left behind its own
        // data and an archive restored into another encoding both exit 0.
        var level2 = new List<Check>();
        var restoredShape = SchemaDdl.Extract(restoredDdl.StandardOutput);
        var declaredShape = contents.Shape;
        var absent = new List<string>();

        Family(level2, absent, "extensions_present",
            declaredShape.Extensions, restoredShape.Extensions, "extension");
        // "statement" for these two, and the count is of statements: pg_dump
        // writes a table over a CREATE TABLE plus an ALTER COLUMN for each
        // default, and a sequence over three. Saying "6 sequences" where the
        // database has two would be a number the reader cannot reconcile with
        // anything they can see.
        Family(level2, absent, "table_definitions_identical",
            declaredShape.Tables, restoredShape.Tables, "table definition statement");
        Family(level2, absent, "sequences_present",
            declaredShape.Sequences, restoredShape.Sequences, "sequence statement");
        Family(level2, absent, "constraints_identical",
            declaredShape.Constraints, restoredShape.Constraints, "constraint");
        Family(level2, absent, "foreign_keys_identical",
            declaredShape.ForeignKeys, restoredShape.ForeignKeys, "foreign key");
        Family(level2, absent, "functions_identical",
            declaredShape.Functions, restoredShape.Functions, "function");
        Family(level2, absent, "triggers_identical",
            declaredShape.Triggers, restoredShape.Triggers, "trigger");

        if (absent.Count > 0)
        {
            // Said once, as an observation, and never as a row of checks that
            // could not be attempted. A database with no triggers did not stop
            // anybody from checking its triggers — there is nothing there — and a
            // level whose list is mostly "nothing to compare" buries the lines
            // that matter.
            observations.Add(
                $"the artefact declares no {Nouns(absent)}, so those comparisons had nothing to compare");
        }

        if (declaredShape.Extensions.Count > 0)
        {
            var installed = await cluster.QueryAsync(RestoredDatabase,
                "SELECT extname || ' ' || extversion FROM pg_extension ORDER BY 1", cancellationToken)
                .ConfigureAwait(false);

            observations.Add(
                "the restored database has extension(s): " +
                string.Join(", ", installed.StandardOutput
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)));

            notAttempted.Add(
                "level 2, extension versions: an archive records which extensions a database had and not which " +
                "version of each, so an extension that came back at a different version than production runs " +
                "cannot be detected from the artefact. The versions restored here are in the observations.");
        }

        await MeasureSequencesAsync(cluster, level2, observations, cancellationToken).ConfigureAwait(false);

        await MeasureRolesAsync(cluster, level2, globals, invented, observations, cancellationToken)
            .ConfigureAwait(false);

        var serverEncoding =(await cluster.QueryAsync(RestoredDatabase, "SHOW server_encoding", cancellationToken)
            .ConfigureAwait(false)).StandardOutput.Trim();

        if (declaredShape.Encoding is { Length: > 0 } declaredEncoding)
        {
            level2.Add(string.Equals(declaredEncoding, serverEncoding, StringComparison.OrdinalIgnoreCase)
                ? new Check("encoding_preserved", Outcome.Passed,
                    $"the artefact was written in {declaredEncoding} and the restored database is {serverEncoding}")
                : new Check("encoding_preserved", Outcome.Failed,
                    $"the artefact was written in {declaredEncoding} and this is a {serverEncoding} database, so " +
                    "every text column has been through a conversion the original never had"));
        }
        else
        {
            notAttempted.Add(
                "level 2, encoding: this artefact does not record the encoding it was written in, so what the " +
                $"restored database ({serverEncoding}) should have been compared against is unknown.");
        }

        // Never left to be assumed, on every run, because it is the one level 2
        // question this design cannot answer from the artefact alone.
        notAttempted.Add(
            "level 2, collation: a pg_dump taken without --create does not record the database's collation, so the " +
            "restored copy is built with the C collation. Text ordering, and every index over a text column, " +
            "follows C rules here whatever the original used — this drill neither checks that they match nor " +
            "claims they do.");

        // ---- level 3: do the guarantees still hold? -------------------------
        var level3 = new List<Check>();
        var restored = SecurityDdl.Extract(restoredDdl.StandardOutput);

        Compare(level3, "rls_enabled_and_forced_preserved",
            contents.Declared.RowLevelSecurity, restored.RowLevelSecurity,
            "row level security statement");
        Compare(level3, "policies_identical",
            contents.Declared.Policies, restored.Policies, "policy");
        Compare(level3, "grants_identical",
            contents.Declared.Grants, restored.Grants, "grant");

        await ExemptionAsync(cluster, level3, globals, notAttempted, cancellationToken).ConfigureAwait(false);

        // Behaviour, not flags. Rule 7 of this repository: the agent is superuser
        // of its own cluster and a superuser bypasses row level security, so
        // "I could read the table" proves nothing. The owner is the interesting
        // role, because FORCE ROW LEVEL SECURITY exists precisely so that the
        // owner is not exempt.
        var forced = ThrowawayCluster.Rows(await cluster.QueryAsync(RestoredDatabase,
            """
            SELECT n.nspname || '.' || c.relname, pg_get_userbyid(c.relowner), o.rolsuper
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_roles o ON o.oid = c.relowner
            WHERE c.relkind = 'r' AND c.relrowsecurity AND c.relforcerowsecurity
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY 1
            """, cancellationToken).ConfigureAwait(false)).Where(row => row.Length == 3).ToList();

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
            var nothingToHide = new List<string>();
            var superuserOwned = new List<string>();

            foreach (var row in probed)
            {
                // A superuser is exempt from row level security unconditionally,
                // and FORCE cannot restrain one — forcing applies to the owner, and
                // this owner would bypass the policy whatever the flag says. It is
                // a fact about the customer's cluster rather than about the
                // restore, and it only becomes visible once the real roles are
                // here: with placeholder roles every owner is an ordinary role and
                // this branch never fires.
                if (row[2].StartsWith('t'))
                {
                    superuserOwned.Add($"{row[0]} (owned by {row[1]})");
                    continue;
                }

                var owner = row[1].Replace("\"", "\"\"", StringComparison.Ordinal);
                var asOwner = await cluster.QueryAsync(RestoredDatabase,
                    $"SET ROLE \"{owner}\"; SELECT count(*) FROM {row[0]}", cancellationToken).ConfigureAwait(false);

                if (!asOwner.Succeeded || !long.TryParse(asOwner.StandardOutput.Trim(), out var visible))
                {
                    unrestricted.Add($"{row[0]} (could not be read as {row[1]})");
                    continue;
                }

                var total = rowCounts.GetValueOrDefault(row[0], 0);

                // An empty table demonstrates nothing in either direction, and
                // reading it as "the owner sees every row" is how this check
                // produced `0 of 0 rows visible` — a sentence that is true, reads
                // as an alarm, and says nothing. It comes up on the archive this
                // product was built to catch, which is the worst place for a line
                // nobody can act on.
                if (total == 0)
                {
                    nothingToHide.Add(row[0]);
                    continue;
                }

                (visible < total ? restricting : unrestricted).Add(
                    $"{row[0]}: {visible} of {total} rows visible to {row[1]}");
            }

            if (restricting.Count == 0 && unrestricted.Count == 0 && superuserOwned.Count > 0)
            {
                level3.Add(new Check("row_level_security_actually_restricts", Outcome.CouldNotAttempt,
                    $"every forced table probed is owned by a superuser: {string.Join(", ", superuserOwned)}. A " +
                    "superuser is never subject to row level security, so FORCE ROW LEVEL SECURITY — which exists " +
                    "to restrain a table's owner — cannot restrain this one. That is a fact about the cluster the " +
                    "backup came from, not about the restore, and an assertion naming the role your application " +
                    "connects as is what turns it into a verdict."));
            }
            else if (restricting.Count == 0 && unrestricted.Count == 0)
            {
                level3.Add(new Check("row_level_security_actually_restricts", Outcome.CouldNotAttempt,
                    $"every forced table probed came back empty ({string.Join(", ", nothingToHide)}), so there is " +
                    "nothing for a policy to hide and nothing to demonstrate. Whether the archive should have been " +
                    "empty is a level 1 question, and it is answered above."));
            }
            else if (unrestricted.Count == 0)
            {
                level3.Add(new Check("row_level_security_actually_restricts", Outcome.Passed,
                    $"with no tenant context set, the owner sees fewer rows than the whole table on all " +
                    $"{restricting.Count} forced table(s): {string.Join("; ", restricting)}" +
                    (superuserOwned.Count == 0
                        ? ""
                        : $". A further {superuserOwned.Count} forced table(s) are owned by a superuser, which no " +
                          $"policy applies to, so they were not probed: {string.Join(", ", superuserOwned)}")));
            }
            else if (superuserOwned.Count > 0)
            {
                // Both kinds in one database. The sentence has to keep them apart:
                // an owner who sees everything because a policy permits it is a
                // different finding from an owner who sees everything because no
                // policy can apply to a superuser.
                level3.Add(new Check("row_level_security_actually_restricts", Outcome.CouldNotAttempt,
                    $"the owner still sees every row of {string.Join("; ", unrestricted)}, and a further " +
                    $"{superuserOwned.Count} forced table(s) are owned by a superuser, which no policy applies to: " +
                    $"{string.Join(", ", superuserOwned)}. The first is what a permissive policy and a lost " +
                    "guarantee both look like; the second is neither, and both are told apart by an assertion " +
                    "naming the role your application connects as."));
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
                    "are told apart by a customer SQL assertion, and " + (pack.IsEmpty
                        ? "this run carried no pack. One assertion — what a named role can see with no tenant " +
                          "set — turns this line into a verdict."
                        : $"this run evaluated {pack.Assertions.Count} of them, below.")));
            }
        }

        // The customer's own questions, asked last because they are asked of a
        // database that has already been compared against its artefact: an
        // assertion that fails against a database which lost a policy is a
        // consequence, and the line above it says so.
        if (pack.IsEmpty)
        {
            notAttempted.Add(
                "level 3, customer SQL assertions: " +
                (pack.Origin is { Length: > 0 } refused ? refused : "none were given") +
                ". The checks above are derived from the artefact and hold for any database; what only you can " +
                "ask — that a named role sees nothing without a tenant, that a view still hides a column — goes " +
                "in an assertion pack. See protocol/v1/ASSERTIONS.md.");
        }
        else
        {
            observations.Add(
                $"{pack.Assertions.Count} customer assertion(s) were evaluated, from {pack.Origin}, as the " +
                $"{AssertionRunner.Role} role: no superuser, no ability to run a program or read a file, and a " +
                "read only transaction" + (globals is null
                    ? ""
                    : ". An assertion naming a role in `as` became that role as your own cluster globals declare " +
                      "it, with its attributes and its memberships"));

            level3.AddRange(await AssertionRunner
                .RunAsync(cluster, RestoredDatabase, pack, globals is not null, observations, notAttempted,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        // A level 2 or level 3 failure is a failed drill. That is the whole
        // product: a backup that restores with every row in place and its
        // guarantees missing — or its sequences behind its data — is not a
        // successful restore. A could-not-attempt never lowers the verdict; it is
        // a correction, and corrections do not decide anything.
        var outcome = checks.Concat(level2).Concat(level3).Any(c => c.Outcome == Outcome.Failed)
            ? Outcome.Failed
            : Outcome.Passed;

        return new DrillReport(
            DrillReport.CurrentVersion, outcome, AgentVersion(), major, startedAt, artefactFacts,
            new Measurements(Math.Round(ageHours, 2), Math.Round(clock.Elapsed.TotalSeconds, 3)),
            checks, level2, level3, rowCounts, observations, notAttempted);
    }

    /// <summary>
    /// Reads the second artefact and puts the customer's own roles into the
    /// throwaway cluster — the step that turns level 3's central question from
    /// something the report says it cannot answer into something it answers.
    /// <para>
    /// <b>The file is read, not executed.</b> What runs is a list of statements
    /// this agent wrote from what it recognised, because a globals artefact is
    /// plain SQL out of somebody's bucket and three kinds of statement in one must
    /// never run here — <see cref="GlobalsDdl"/> says which and why. Everything it
    /// declined is reported: a reader who is told the globals were applied would
    /// otherwise assume all of them were.
    /// </para>
    /// <para>
    /// Every failure here is a correction and never a verdict. A globals artefact
    /// that cannot be read says nothing about whether the backup restores, so the
    /// drill goes on without it and the report says the roles are placeholders —
    /// which is exactly where this product was before this artefact existed.
    /// </para>
    /// </summary>
    private static async Task<AppliedGlobals?> ApplyGlobalsAsync(
        ThrowawayCluster cluster,
        GlobalsArtefact? artefact,
        ArtefactFacts backup,
        List<string> observations,
        List<string> notAttempted,
        CancellationToken cancellationToken)
    {
        if (artefact is null)
        {
            return null;
        }

        string text;
        try
        {
            text = await File.ReadAllTextAsync(artefact.Path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            notAttempted.Add(
                $"the cluster globals: '{artefact.Name}' could not be read ({exception.Message}), so the roles in " +
                "this drill are placeholders and level 3's role questions were not asked.");
            return null;
        }

        var globals = GlobalsDdl.Read(text, [ThrowawayCluster.SuperUser, AssertionRunner.Role]);

        foreach (var sentence in globals.Refused)
        {
            notAttempted.Add($"the cluster globals, not applied — {sentence}");
        }

        if (globals.IsEmpty)
        {
            notAttempted.Add(
                $"the cluster globals: '{artefact.Name}' carries no role this agent recognises. A globals artefact " +
                "is what `pg_dumpall --globals-only` writes; if that pattern is matching something else in the " +
                "bucket, the roles in this drill are placeholders and level 3's role questions were not asked.");
            return null;
        }

        var statements = GlobalsDdl.Statements(globals);
        var applied = statements.Take(GlobalsDdl.StatementCeiling).ToList();
        if (statements.Count > applied.Count)
        {
            // Never a silent cap, here least of all: the roles that fell off the
            // end are the ones a later check would report as missing, and a reader
            // would take that for a finding about their backup.
            notAttempted.Add(
                $"the cluster globals: '{artefact.Name}' asks for {statements.Count} statements and this agent " +
                $"applies at most {GlobalsDdl.StatementCeiling} in one drill, so {statements.Count - applied.Count} " +
                "were not applied. The roles below that are reported as missing may be among them.");
        }

        var failures = new List<string>();
        foreach (var statement in applied)
        {
            var result = await cluster.QueryAsync("postgres", statement, cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                failures.Add($"{statement} — {FirstErrors(result.StandardError)}");
            }
        }

        var written = (artefact.LastModified - backup.LastModified).TotalHours;
        observations.Add(
            $"the cluster globals came from '{artefact.Name}' ({Bytes(artefact.SizeBytes)}, written " +
            $"{Math.Abs(written):0.0} h {(written < 0 ? "before" : "after")} the backup): " +
            $"{globals.Roles.Count} role(s) and {globals.Memberships.Count} membership(s), applied with their " +
            "attributes and without their password verifiers, connection limits or validity dates — none of those " +
            "is readable from a report and this cluster has no listener to authenticate anybody against");

        // The authorization model, in one line, for the person who has to describe
        // it to an auditor. It is the sentence that cannot be written without this
        // artefact, and it is worth its own place in the report even when every
        // check below passes.
        var powerful = globals.Roles
            .Where(role => role.Attributes.Superuser || role.Attributes.BypassRls)
            .Select(role => $"{role.Name} ({role.Attributes.Held()})")
            .ToList();

        observations.Add(powerful.Count == 0
            ? "no role in the cluster globals holds SUPERUSER or BYPASSRLS, so every role there is subject to the " +
              "policies written about it"
            : $"{powerful.Count} role(s) in the cluster globals are exempt from row level security, because a " +
              $"superuser always is and BYPASSRLS says so outright: {string.Join(", ", powerful)}");

        return new AppliedGlobals(globals.Roles, failures);
    }

    /// <summary>
    /// Level 2's role questions, and they exist only when a globals artefact was
    /// applied: without one there are no declared attributes to compare against
    /// and the report says so under what it did not check.
    /// <para>
    /// The second of the two is the one worth having. A backup and a globals
    /// artefact that disagree about which roles exist are not a matched pair —
    /// the file is older than the database it is supposed to describe, or it was
    /// truncated, or it came from a different cluster — and the symptom is a
    /// restored database whose objects belong to roles nobody can describe.
    /// </para>
    /// </summary>
    private static async Task MeasureRolesAsync(
        ThrowawayCluster cluster,
        List<Check> level2,
        AppliedGlobals? globals,
        IReadOnlyList<string> invented,
        List<string> observations,
        CancellationToken cancellationToken)
    {
        if (globals is null)
        {
            return;
        }

        var probe = await cluster.QueryAsync("postgres",
            """
            SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb,
                   rolcanlogin, rolreplication, rolbypassrls
            FROM pg_roles
            ORDER BY 1
            """, cancellationToken).ConfigureAwait(false);

        if (!probe.Succeeded)
        {
            level2.Add(new Check("roles_present_with_their_attributes", Outcome.CouldNotAttempt,
                probe.Describe("asking the restored cluster about its roles")));
            return;
        }

        var actual = new Dictionary<string, RoleAttributes>(StringComparer.Ordinal);
        foreach (var row in ThrowawayCluster.Rows(probe).Where(row => row.Length == 8))
        {
            actual[row[0]] = new RoleAttributes(
                Superuser: row[1].StartsWith('t'),
                Inherit: row[2].StartsWith('t'),
                CreateRole: row[3].StartsWith('t'),
                CreateDb: row[4].StartsWith('t'),
                Login: row[5].StartsWith('t'),
                Replication: row[6].StartsWith('t'),
                BypassRls: row[7].StartsWith('t'));
        }

        var wrong = new List<string>();
        foreach (var role in globals.Roles)
        {
            if (!actual.TryGetValue(role.Name, out var found))
            {
                wrong.Add($"{role.Name} is not in the restored cluster at all");
                continue;
            }

            var differences = role.Attributes.Differences(found);
            if (differences.Count > 0)
            {
                wrong.Add($"{role.Name}: {string.Join(", ", differences)}");
            }
        }

        // A statement that failed is why a role is missing, so it belongs in the
        // same sentence rather than in a separate line somebody has to join up.
        var refusals = globals.Failures.Count == 0
            ? ""
            : $" {globals.Failures.Count} statement(s) out of the globals artefact did not apply: " +
              string.Join(" | ", globals.Failures);

        level2.Add(wrong.Count == 0
            ? new Check("roles_present_with_their_attributes", Outcome.Passed,
                $"all {globals.Roles.Count} role(s) the globals artefact declares are in the restored cluster with " +
                $"the attributes it declared{refusals}")
            : new Check("roles_present_with_their_attributes", Outcome.Failed,
                $"{wrong.Count} of {globals.Roles.Count} role(s) did not come back as declared: " +
                $"{string.Join("; ", wrong)}.{refusals}"));

        level2.Add(invented.Count == 0
            ? new Check("globals_carry_every_role_the_backup_uses", Outcome.Passed,
                "every role the backup's objects belong to or grant to is declared by the globals artefact, so the " +
                "two artefacts describe the same cluster")
            : new Check("globals_carry_every_role_the_backup_uses", Outcome.Failed,
                $"the globals artefact does not declare {invented.Count} role(s) the backup's own objects reference: " +
                $"{string.Join(", ", invented)}. They were created empty so the restore could finish, and what they " +
                "hold in production is in neither artefact. A globals file older than the backup beside it, a " +
                "truncated one, and one taken from a different cluster all look like this."));

        if (invented.Count > 0)
        {
            observations.Add(
                $"{invented.Count} role(s) were created empty because the globals artefact does not declare them: " +
                string.Join(", ", invented));
        }
    }

    /// <summary>
    /// The question this whole second artefact exists for: <b>is any role a policy
    /// names exempt from it?</b>
    /// <para>
    /// A policy that names a role exists in order to restrain that role. A role
    /// holding <c>BYPASSRLS</c> is exempt from every policy in the database, and a
    /// superuser is exempt whether anybody said so or not — so a database can come
    /// back with every row in place, every policy byte-identical to the artefact's,
    /// forced row level security on every table, and the policies still cannot
    /// bite. Nothing derived from a per-database dump can see it, because the
    /// attribute that decides it is cluster-wide and is not in that file.
    /// </para>
    /// <para>
    /// Read from <c>pg_policy.polroles</c> rather than from the DDL: it is the
    /// catalogue's own answer to "which roles is this policy about", and it holds
    /// the roles as they are after the restore. <c>0</c> in that array is PUBLIC,
    /// which is not a role and never joins.
    /// </para>
    /// </summary>
    private static async Task ExemptionAsync(
        ThrowawayCluster cluster,
        List<Check> level3,
        AppliedGlobals? globals,
        List<string> notAttempted,
        CancellationToken cancellationToken)
    {
        if (globals is null)
        {
            // Said once, by the caller, with the instruction attached: without the
            // globals artefact there is no attribute to read, and a check that
            // reported "no role is exempt" from a cluster whose roles are all
            // placeholders would be a false pass on the sharpest question here.
            return;
        }

        var probe = await cluster.QueryAsync(RestoredDatabase,
            """
            SELECT r.rolname, r.rolsuper, r.rolbypassrls
            FROM pg_policy p, unnest(p.polroles) AS named(oid), pg_roles r
            WHERE r.oid = named.oid
            GROUP BY 1, 2, 3
            ORDER BY 1
            """, cancellationToken).ConfigureAwait(false);

        if (!probe.Succeeded)
        {
            level3.Add(new Check("no_role_is_exempt_from_a_policy_that_names_it", Outcome.CouldNotAttempt,
                probe.Describe("asking the restored database which roles its policies name")));
            return;
        }

        var named = ThrowawayCluster.Rows(probe).Where(row => row.Length == 3).ToList();
        if (named.Count == 0)
        {
            notAttempted.Add(
                "level 3, role exemption: no policy in the restored database names a role — they all apply to " +
                "PUBLIC — so there is no named role that could be exempt from one. The cluster globals were still " +
                "read, and which roles hold SUPERUSER or BYPASSRLS is in the observations.");
            return;
        }

        var exempt = named
            .Where(row => row[1].StartsWith('t') || row[2].StartsWith('t'))
            .Select(row => $"{row[0]} ({(row[1].StartsWith('t') ? "SUPERUSER" : "BYPASSRLS")})")
            .ToList();

        level3.Add(exempt.Count == 0
            ? new Check("no_role_is_exempt_from_a_policy_that_names_it", Outcome.Passed,
                $"all {named.Count} role(s) named by a policy in this database are subject to it: none of them holds " +
                "SUPERUSER, and none holds BYPASSRLS")
            : new Check("no_role_is_exempt_from_a_policy_that_names_it", Outcome.Failed,
                $"{exempt.Count} of {named.Count} role(s) named by a policy are exempt from every policy in this " +
                $"database: {string.Join(", ", exempt)}. A policy naming a role exists to restrain that role, and " +
                "BYPASSRLS and SUPERUSER are read before any policy is. The rows came back, the policies are " +
                "identical to the artefact's, and they cannot bite this role."));
    }

    /// <summary>
    /// The sequence question, asked of the restored database because no DDL can
    /// answer it: for every sequence a column owns, is the next value it will
    /// hand out above the largest value already stored?
    /// <para>
    /// A sequence that came back behind its own data does not fail the restore.
    /// It exits zero, the row counts are right, the DDL matches — and the next
    /// INSERT fails with a duplicate key, weeks later, on a database somebody was
    /// told had been verified. It is the level 2 failure that is invisible
    /// everywhere else, which is why it is worth two queries.
    /// </para>
    /// </summary>
    private static async Task MeasureSequencesAsync(
        ThrowawayCluster cluster,
        List<Check> level2,
        List<string> observations,
        CancellationToken cancellationToken)
    {
        var probe = await cluster.QueryAsync(RestoredDatabase, SequenceProbe, cancellationToken)
            .ConfigureAwait(false);

        if (!probe.Succeeded)
        {
            level2.Add(new Check("sequences_ahead_of_their_data", Outcome.CouldNotAttempt,
                probe.Describe("asking the restored database about its sequences")));
            return;
        }

        var rows = ThrowawayCluster.Rows(probe).Where(row => row.Length == 6).ToList();
        if (rows.Count == 0)
        {
            return;
        }

        var behind = new List<string>();
        var measured = 0;
        var empty = 0;

        foreach (var row in rows)
        {
            if (!long.TryParse(row[4], out var next))
            {
                behind.Add($"{row[0]} could not be read at all");
                continue;
            }

            // No rows in the column means nothing for the sequence to be behind.
            // Counted rather than dropped: a level whose numbers do not add up
            // invites the reader to guess which ones were skipped.
            if (!long.TryParse(row[5], out var largest))
            {
                empty++;
                continue;
            }

            measured++;
            if (next <= largest)
            {
                behind.Add($"{row[0]} will hand out {next} and {row[1]}.{row[2]} already holds {largest}");
            }
        }

        if (long.TryParse(rows[0][3], out var total) && total > rows.Count)
        {
            // Never a silent cap: a truncated check that reads like a complete one
            // is how a report starts overstating what it covered.
            observations.Add(
                $"sequences were measured on {rows.Count} of {total} owned by a column (per run ceiling)");
        }

        if (behind.Count > 0)
        {
            level2.Add(new Check("sequences_ahead_of_their_data", Outcome.Failed,
                $"{behind.Count} sequence(s) came back behind their own data: {string.Join("; ", behind)}. " +
                "The restore exited clean and the rows are all there; the next insert into each of those tables " +
                "fails with a duplicate key."));
            return;
        }

        var note = empty == 0 ? "" : $", and {empty} more own a column with no rows in it to be behind";
        level2.Add(new Check("sequences_ahead_of_their_data", Outcome.Passed,
            $"all {measured} sequence(s) owned by a column will hand out a value above the largest already " +
            $"stored{note}"));
    }

    /// <summary>
    /// One guarantee, level 3. An artefact that declares none of a guarantee is
    /// worth saying out loud — a database with no policy at all is a fact about
    /// the backup, not a quiet pass.
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
                $"the artefact declares no {noun}, so there is nothing to preserve." +
                (restored.Count == 0 ? "" : $" The restored database has {restored.Count}, which it should not.")));
            return;
        }

        checks.Add(Compared(key, declared, restored, noun));
    }

    /// <summary>
    /// One family of level 2 statements, and silent when the database has none of
    /// them: a database with no trigger did not stop anybody from checking its
    /// triggers. What is absent is named once, by the caller, in a single
    /// observation.
    /// <para>
    /// A family the artefact does not declare and the restored database has is
    /// still compared, and still fails. An object that appeared is as much a
    /// finding as one that was lost.
    /// </para>
    /// </summary>
    private static void Family(
        List<Check> checks,
        List<string> absent,
        string key,
        IReadOnlySet<string> declared,
        IReadOnlySet<string> restored,
        string noun)
    {
        if (declared.Count == 0 && restored.Count == 0)
        {
            absent.Add(noun);
            return;
        }

        checks.Add(Compared(key, declared, restored, noun));
    }

    /// <summary>
    /// Two sets of statements compared in both directions. A restored database
    /// that <em>gained</em> a policy — or a constraint, or a trigger — is as much
    /// a finding as one that lost it: either way it is not the database the
    /// artefact describes.
    /// </summary>
    private static Check Compared(
        string key,
        IReadOnlySet<string> declared,
        IReadOnlySet<string> restored,
        string noun)
    {
        var (lost, gained) = Ddl.Difference(declared, restored);

        if (lost.Count == 0 && gained.Count == 0)
        {
            return new Check(key, Outcome.Passed,
                $"all {declared.Count} {noun}(s) the artefact declares are present in the restored database, identical");
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

        return new Check(key, Outcome.Failed, string.Join("; ", detail));
    }

    /// <summary>An English list of plurals: "extensions, functions or triggers".</summary>
    private static string Nouns(IReadOnlyList<string> nouns) => nouns.Count == 1
        ? $"{nouns[0]}s"
        : string.Join(", ", nouns.Take(nouns.Count - 1).Select(noun => $"{noun}s")) + $" or {nouns[^1]}s";

    /// <summary>
    /// The encoding to build the throwaway cluster with: the artefact's own, and
    /// UTF8 only when the artefact does not record one. The shape is checked
    /// because this value comes out of a file somebody else wrote, and initdb
    /// handed a word it does not know fails with a message about the word rather
    /// than about the artefact.
    /// </summary>
    private static string ClusterEncoding(string? declared, List<string> observations)
    {
        if (declared is null or "")
        {
            return DefaultEncoding;
        }

        if (!EncodingName().IsMatch(declared))
        {
            observations.Add(
                $"the artefact names an encoding this agent will not hand to initdb ('{declared}'), so the " +
                $"restored database is {DefaultEncoding}");
            return DefaultEncoding;
        }

        return declared;
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

    /// <summary>
    /// What this agent calls itself, on the wire and on the screen.
    /// <para>
    /// <c>AssemblyInformationalVersion</c> carries what the build was given —
    /// <c>1.0.0</c> — while <c>GetName().Version</c> is the assembly version,
    /// which MSBuild pads to four parts. The padded form reached the first
    /// release: <c>proofdrill version</c> printed <c>1.0.0.0</c>, and that
    /// string is not decoration. It is signed material inside the report and the
    /// claim envelopes, and the field is documented in a protocol other people
    /// implement against — where <c>JOBS.md</c> shows a three-part version. Two
    /// shapes in one public field is a comparison somebody writes wrongly later,
    /// and the "warn when an agent is too old" rule in <c>docs/03</c> §11.1 is
    /// exactly that comparison, not yet written.
    /// </para>
    /// <para>
    /// The <c>+commit</c> suffix is cut because the SDK appends one when the
    /// build can see a git revision. Without cutting it, a build from a working
    /// tree and a build from a Docker context — which copies no <c>.git</c> —
    /// would report different versions for identical source.
    /// </para>
    /// </summary>
    public static string AgentVersion()
    {
        var informational = typeof(DrillRunner).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .FirstOrDefault()?.InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informational))
        {
            var plus = informational.IndexOf('+', StringComparison.Ordinal);
            return plus < 0 ? informational : informational[..plus];
        }

        return typeof(DrillRunner).Assembly.GetName().Version?.ToString() ?? "0.0.0";
    }

    [GeneratedRegex(@"Dumped from database version:\s*(?<major>\d+)")]
    private static partial Regex DumpedFrom();

    [GeneratedRegex(@"^[A-Za-z0-9_]{1,32}$")]
    private static partial Regex EncodingName();
}
