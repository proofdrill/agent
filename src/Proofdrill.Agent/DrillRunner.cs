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

        var serverEncoding = (await cluster.QueryAsync(RestoredDatabase, "SHOW server_encoding", cancellationToken)
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

        notAttempted.Add("level 3, customer SQL assertions: not implemented yet");

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
                $"the artefact declares no {noun}, so there is nothing to preserve. " +
                (restored.Count == 0 ? "" : $"The restored database has {restored.Count}, which it should not.")));
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

    public static string AgentVersion() =>
        typeof(DrillRunner).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    [GeneratedRegex(@"Dumped from database version:\s*(?<major>\d+)")]
    private static partial Regex DumpedFrom();

    [GeneratedRegex(@"^[A-Za-z0-9_]{1,32}$")]
    private static partial Regex EncodingName();
}
