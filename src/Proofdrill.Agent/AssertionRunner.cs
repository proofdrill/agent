using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace Proofdrill.Agent;

/// <summary>
/// The customer's own assertions, evaluated against the restored database.
/// <para>
/// <b>The boundary is the role, not a parser.</b> Nothing here inspects the SQL
/// looking for dangerous words. A filter that accepts a language and forbids a
/// subset of it is a promise that breaks on the first function nobody thought
/// of, and it would read as a guarantee in exactly the document that must not
/// contain one. What bounds this instead is what the statement runs <em>as</em>:
/// a role created here with no superuser, no membership of
/// <c>pg_execute_server_program</c> or <c>pg_read_server_files</c>, inside a read
/// only transaction with a timeout, against a cluster that has no TCP listener
/// and is deleted when the drill ends.
/// </para>
/// <para>
/// That distinction is the whole reason this feature is safe to have at all,
/// because the statement can arrive from the control plane — and a control plane
/// that could make an agent run a program inside a customer's perimeter would be
/// worth breaking into. It cannot: <c>COPY … FROM PROGRAM</c> needs privileges
/// this role does not have and cannot grant itself.
/// </para>
/// </summary>
internal static partial class AssertionRunner
{
    /// <summary>
    /// The role every customer statement runs as. Named for what it is, so that
    /// somebody reading <c>pg_stat_activity</c> on a machine they own knows which
    /// process is ours.
    /// </summary>
    public const string Role = "proofdrill_assert";

    /// <summary>
    /// PostgreSQL 14 and later. It grants SELECT on every table and USAGE on
    /// every schema, and it does <b>not</b> grant BYPASSRLS — which is what makes
    /// it the right privilege here: an assertion can reach every table without
    /// being exempt from the guarantees this product exists to check.
    /// </summary>
    private const string ReadAllData = "pg_read_all_data";

    /// <summary>One assertion's share of the machine. Long enough for a sequential scan over a real table.</summary>
    private static readonly TimeSpan PerAssertion = TimeSpan.FromSeconds(30);

    /// <summary>
    /// What the whole pack may spend. This runs on somebody's backup host, often
    /// at night, and a drill that has already answered levels 1 to 3 must not be
    /// held open indefinitely by a query nobody profiled.
    /// </summary>
    private static readonly TimeSpan PackBudget = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The SQLSTATEs a customer writing assertions actually meets. Codes rather
    /// than messages, because rule 8 of this repository applies with force here:
    /// a PostgreSQL error message can quote the row that caused it, and this text
    /// leaves the perimeter.
    /// </summary>
    private static readonly Dictionary<string, string> Conditions = new(StringComparer.Ordinal)
    {
        ["42501"] = "insufficient_privilege — the role this ran as may not read what the statement asks for",
        ["42P01"] = "undefined_table — the statement names a table the restored database does not have",
        ["42703"] = "undefined_column",
        ["42601"] = "syntax_error — one statement per assertion, and it must be a single SELECT",
        ["42P02"] = "undefined_parameter",
        ["22023"] = "invalid_parameter_value — a setting this assertion asked for was not accepted",
        ["25006"] = "read_only_sql_transaction — an assertion asks a question, it does not change anything",
        ["57014"] = "query_canceled — it ran past the per-assertion timeout",
        ["55P03"] = "lock_not_available",
    };

    /// <summary>
    /// Runs the pack and returns its checks, in the order the customer wrote
    /// them. Never throws for a bad assertion: a statement that cannot run is a
    /// correction and never a verdict, exactly like every other could-not-attempt
    /// in this product.
    /// </summary>
    public static async Task<IReadOnlyList<Check>> RunAsync(
        ThrowawayCluster cluster,
        string database,
        AssertionPack pack,
        List<string> observations,
        List<string> notAttempted,
        CancellationToken cancellationToken)
    {
        var checks = new List<Check>();

        var prepared = await PrepareAsync(cluster, database, observations, cancellationToken).ConfigureAwait(false);
        if (prepared is { } refusal)
        {
            notAttempted.Add(
                $"level 3, customer SQL assertions: none of the {pack.Assertions.Count} in this pack were " +
                $"evaluated, because the role they run as could not be created. {refusal}");
            return checks;
        }

        var roles = await RolesAsync(cluster, database, pack, cancellationToken).ConfigureAwait(false);
        var clock = Stopwatch.StartNew();

        foreach (var assertion in pack.Assertions)
        {
            if (clock.Elapsed > PackBudget)
            {
                // Never a silent cap. A pack whose tail was skipped and read as
                // passed is the same defect as a truncated check, and this one is
                // the customer's own question going unanswered.
                checks.Add(new Check(Key(assertion), Outcome.CouldNotAttempt,
                    $"{assertion.Title} — not evaluated: the pack's budget of {PackBudget.TotalMinutes:0} minutes " +
                    "was already spent"));
                continue;
            }

            if (assertion.Role is { } named && roles.TryGetValue(named, out var why))
            {
                checks.Add(new Check(Key(assertion), Outcome.CouldNotAttempt, $"{assertion.Title} — {why}"));
                continue;
            }

            checks.Add(await OneAsync(cluster, database, assertion, cancellationToken).ConfigureAwait(false));
        }

        return checks;
    }

    /// <summary>
    /// Creates the role the statements run as, and returns null when it worked.
    /// <para>
    /// It is created here rather than reused from the artefact on purpose: a role
    /// out of a customer's own dump carries their attributes and their
    /// memberships, and "what this ran as" would then be a different thing on
    /// every database in the world.
    /// </para>
    /// </summary>
    private static async Task<string?> PrepareAsync(
        ThrowawayCluster cluster,
        string database,
        List<string> observations,
        CancellationToken cancellationToken)
    {
        var exists = await cluster.QueryAsync(database,
            $"SELECT 1 FROM pg_roles WHERE rolname = '{Role}'", cancellationToken).ConfigureAwait(false);

        if (!exists.Succeeded)
        {
            return exists.Describe("asking the restored cluster about its roles");
        }

        // LOGIN and a direct connection, never SET ROLE from the superuser
        // session. A session whose *session* role is a superuser can RESET ROLE
        // and get it back, so a statement running under SET ROLE is bounded by
        // convention rather than by the server. Connecting as this role means the
        // server holds the boundary.
        //
        // BYPASSRLS, and it is the opposite of what it looks like. An assertion
        // with no `as` is asking about the DATA — "this table is not empty",
        // "no row lost its parent" — and every buyer of this product has row
        // level security on the tables it would ask about. Without the exemption,
        // `SELECT count(*) = 0 FROM orders` reads zero rows because a policy hid
        // them and passes: a silent false PASS, on the assertion somebody wrote
        // precisely because they did not trust the backup. It also puts two
        // numbers that contradict each other in one report, since the row counts
        // above are read by the superuser.
        //
        // Naming a role in `as` takes the exemption away, because SET ROLE
        // changes current_user and PostgreSQL evaluates both the policies and the
        // BYPASSRLS attribute against that. So the default answers questions
        // about data, and `as` answers questions about guarantees — and no
        // arrangement of the two produces a false pass.
        var attributes =
            "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS INHERIT";

        var made = exists.StandardOutput.Trim().Length > 0
            ? await cluster.QueryAsync(database, $"ALTER ROLE {Role} {attributes}", cancellationToken)
                .ConfigureAwait(false)
            : await cluster.QueryAsync(database, $"CREATE ROLE {Role} {attributes}", cancellationToken)
                .ConfigureAwait(false);

        if (!made.Succeeded)
        {
            return made.Describe($"creating the '{Role}' role");
        }

        var readAll = await cluster.QueryAsync(database,
            $"SELECT 1 FROM pg_roles WHERE rolname = '{ReadAllData}'", cancellationToken).ConfigureAwait(false);

        if (readAll.Succeeded && readAll.StandardOutput.Trim().Length > 0)
        {
            var granted = await cluster.QueryAsync(database, $"GRANT {ReadAllData} TO {Role}", cancellationToken)
                .ConfigureAwait(false);

            if (!granted.Succeeded)
            {
                return granted.Describe($"granting {ReadAllData} to '{Role}'");
            }
        }
        else
        {
            // PostgreSQL 13 and older. Said out loud rather than left to produce a
            // wall of permission denied: the assertions still run, and they see
            // only what the artefact's own grants allow.
            observations.Add(
                $"this cluster has no {ReadAllData} role (PostgreSQL 13 or older), so the customer assertions run " +
                "with only the privileges the artefact itself grants");
        }

        return null;
    }

    /// <summary>
    /// Checks every role the pack names, once, and returns the ones that cannot
    /// be used with the reason. The rest are granted to the assertion role so that
    /// <c>SET ROLE</c> succeeds.
    /// <para>
    /// A superuser is refused by name. Becoming one would hand a customer
    /// statement — which may have arrived from the control plane — the ability to
    /// read files and run programs on the machine this agent was installed on,
    /// and every promise in this repository's README rests on that being
    /// impossible.
    /// </para>
    /// </summary>
    private static async Task<Dictionary<string, string>> RolesAsync(
        ThrowawayCluster cluster,
        string database,
        AssertionPack pack,
        CancellationToken cancellationToken)
    {
        var refused = new Dictionary<string, string>(StringComparer.Ordinal);
        var named = pack.Assertions
            .Select(assertion => assertion.Role)
            .OfType<string>()
            .Distinct(StringComparer.Ordinal);

        foreach (var role in named)
        {
            var quoted = Literal(role);
            var found = await cluster.QueryAsync(database,
                $"SELECT rolsuper FROM pg_roles WHERE rolname = {quoted}", cancellationToken).ConfigureAwait(false);

            var answer = found.StandardOutput.Trim();

            if (!found.Succeeded || answer.Length == 0)
            {
                refused[role] = $"the restored cluster has no role called '{role}'. A per-database artefact does " +
                    "not carry roles at all, so the only ones here are those the artefact referenced and this " +
                    "agent created empty to let the restore finish.";
                continue;
            }

            if (answer.StartsWith('t'))
            {
                refused[role] = $"'{role}' is a superuser in the restored cluster, and this agent does not run a " +
                    "customer statement as a superuser: a superuser can read files and run programs on this " +
                    "machine. Ask that question of the catalogue instead.";
                continue;
            }

            var granted = await cluster.QueryAsync(database,
                $"GRANT {Identifier(role)} TO {Role}", cancellationToken).ConfigureAwait(false);

            if (!granted.Succeeded)
            {
                refused[role] = granted.Describe($"granting '{role}' to the assertion role");
            }
        }

        return refused;
    }

    private static async Task<Check> OneAsync(
        ThrowawayCluster cluster,
        string database,
        Assertion assertion,
        CancellationToken cancellationToken)
    {
        var script = new StringBuilder();

        // READ ONLY is not the boundary — the role is — but it turns an assertion
        // that writes into an error the customer sees on the first run, instead of
        // a pack whose third assertion quietly depends on what its second one did
        // to the data.
        script.Append("BEGIN READ ONLY; ");
        script.Append($"SET LOCAL statement_timeout = '{PerAssertion.TotalSeconds:0}s'; ");
        script.Append("SET LOCAL lock_timeout = '5s'; ");

        foreach (var (name, value) in assertion.Settings)
        {
            // The name is already known to match a parameter's shape, and the
            // value goes in as a literal. SET rather than set_config() because
            // set_config is a SELECT and would print a row into the answer this
            // reads back.
            script.Append($"SET LOCAL {name} = {Literal(value)}; ");
        }

        if (assertion.Role is { } role)
        {
            script.Append($"SET LOCAL ROLE {Identifier(role)}; ");
        }

        // Wrapped, so that the answer's shape is decided here rather than by the
        // statement. An assertion that returns two rows, or a number, or that is
        // really two statements with a semicolon between them, produces something
        // that is not a single `t` or `f` — and that is reported as an assertion
        // which could not be evaluated rather than as one that failed.
        script.Append($"WITH proofdrill_assertion AS ({assertion.Sql}) SELECT * FROM proofdrill_assertion;");

        var result = await cluster
            .QueryAsAsync(Role, database, script.ToString(), PerAssertion + TimeSpan.FromSeconds(30), cancellationToken)
            .ConfigureAwait(false);

        var context = Context(assertion);

        if (!result.Succeeded)
        {
            // The full message stays on this machine. It can quote the row that
            // caused it — a duplicate key error names the value — and PROTOCOL.md
            // §1 says no row of data leaves the perimeter, which includes the
            // rows inside an error message.
            await Console.Error.WriteLineAsync(
                $"proofdrill: assertion '{assertion.Key}' did not run: {result.StandardError.Trim().ReplaceLineEndings(" ")}")
                .ConfigureAwait(false);

            return new Check(Key(assertion), Outcome.CouldNotAttempt,
                $"{assertion.Title} — could not be evaluated{context}: {Condition(result.StandardError)}. " +
                "The database's own message is on the terminal of the machine that ran this, and not in this " +
                "report: an error can quote the row that caused it.");
        }

        var lines = result.StandardOutput
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (lines is ["t"])
        {
            return new Check(Key(assertion), Outcome.Passed, $"{assertion.Title} — held{context}");
        }

        if (lines is ["f"])
        {
            return new Check(Key(assertion), Outcome.Failed, $"{assertion.Title} — did NOT hold{context}");
        }

        return new Check(Key(assertion), Outcome.CouldNotAttempt,
            $"{assertion.Title} — could not be evaluated{context}: an assertion must return exactly one row with " +
            $"one boolean column, and this one returned {lines.Length} row(s). Write it as a comparison: " +
            "SELECT count(*) = 0 FROM …");
    }

    /// <summary>
    /// The role and the setting NAMES, and never a setting's value. A value is
    /// written by the customer and can be a tenant id, an address or anything
    /// else out of their data; the name is configuration and says what was asked
    /// without saying what was asked about.
    /// </summary>
    private static string Context(Assertion assertion)
    {
        var parts = new List<string>();
        if (assertion.Role is { } role)
        {
            parts.Add($"as {role}");
        }

        if (assertion.Settings.Count > 0)
        {
            parts.Add($"with {string.Join(", ", assertion.Settings.Select(setting => setting.Key))} set");
        }

        return parts.Count == 0 ? "" : $" ({string.Join(", ", parts)})";
    }

    /// <summary>
    /// The SQLSTATE, read out of psql's verbose form, and the condition name for
    /// the ones a customer meets. Never the message: this is rule 8 and it is also
    /// §1 of the protocol.
    /// </summary>
    private static string Condition(string standardError)
    {
        var match = SqlState().Match(standardError);
        if (!match.Success)
        {
            return "the statement failed and PostgreSQL reported no SQLSTATE";
        }

        var state = match.Groups["state"].Value;
        return Conditions.TryGetValue(state, out var known)
            ? $"SQLSTATE {state}, {known}"
            : $"SQLSTATE {state}";
    }

    /// <summary>
    /// The report's key for one assertion. Prefixed so that a reader can tell
    /// whose question it is — and so that a customer cannot name an assertion
    /// <c>policies_identical</c> and have it read as one of ours.
    /// </summary>
    public static string Key(Assertion assertion) => $"assertion_{assertion.Key}";

    /// <summary>A string literal, with the one escape pg_dump's own dialect uses.</summary>
    private static string Literal(string value) =>
        $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";

    /// <summary>A quoted identifier. Role names carry spaces and capitals more often than people expect.</summary>
    private static string Identifier(string value) =>
        $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";

    // psql --variable=VERBOSITY=verbose prints `ERROR:  42501: permission denied…`.
    [GeneratedRegex(@"ERROR:\s+(?<state>[0-9A-Z]{5}):", RegexOptions.Multiline)]
    private static partial Regex SqlState();
}
