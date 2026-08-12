using System.Text;

namespace Proofdrill.Agent;

/// <summary>
/// The seven attributes a role either holds or does not, and the only thing this
/// agent takes from a globals artefact besides the role's name and its
/// memberships.
/// <para>
/// They are the whole of what level 3 can ask about a role: <c>BYPASSRLS</c> and
/// <c>SUPERUSER</c> decide whether a policy naming that role can bite at all, and
/// the other five are the authorization model an auditor asks to see. A password
/// verifier, a connection limit and a validity date are none of level 3's
/// business, and <see cref="GlobalsDdl"/> drops them rather than loading them
/// into a cluster that has no listener to authenticate anybody against.
/// </para>
/// </summary>
internal readonly record struct RoleAttributes(
    bool Superuser,
    bool Inherit,
    bool CreateRole,
    bool CreateDb,
    bool Login,
    bool Replication,
    bool BypassRls)
{
    /// <summary>What <c>CREATE ROLE x</c> alone produces, which is what a file that names no attributes means.</summary>
    public static RoleAttributes Default => new(false, true, false, false, false, false, false);

    /// <summary>The attributes as PostgreSQL spells them, all seven, none left to a default.</summary>
    public string Clause() =>
        $"{(Superuser ? "" : "NO")}SUPERUSER {(Inherit ? "" : "NO")}INHERIT " +
        $"{(CreateRole ? "" : "NO")}CREATEROLE {(CreateDb ? "" : "NO")}CREATEDB " +
        $"{(Login ? "" : "NO")}LOGIN {(Replication ? "" : "NO")}REPLICATION " +
        $"{(BypassRls ? "" : "NO")}BYPASSRLS";

    /// <summary>
    /// Only the attributes actually held, for a sentence somebody reads. A list of
    /// seven words of which five begin with NO says nothing; "SUPERUSER,
    /// BYPASSRLS" is the finding.
    /// </summary>
    public string Held()
    {
        var held = new List<string>();
        if (Superuser) held.Add("SUPERUSER");
        if (CreateRole) held.Add("CREATEROLE");
        if (CreateDb) held.Add("CREATEDB");
        if (Login) held.Add("LOGIN");
        if (Replication) held.Add("REPLICATION");
        if (BypassRls) held.Add("BYPASSRLS");
        if (!Inherit) held.Add("NOINHERIT");

        return held.Count == 0 ? "no attributes" : string.Join(", ", held);
    }

    /// <summary>Every attribute where two readings disagree, named one by one.</summary>
    public IReadOnlyList<string> Differences(RoleAttributes other)
    {
        var differences = new List<string>();
        Compare(differences, "SUPERUSER", Superuser, other.Superuser);
        Compare(differences, "INHERIT", Inherit, other.Inherit);
        Compare(differences, "CREATEROLE", CreateRole, other.CreateRole);
        Compare(differences, "CREATEDB", CreateDb, other.CreateDb);
        Compare(differences, "LOGIN", Login, other.Login);
        Compare(differences, "REPLICATION", Replication, other.Replication);
        Compare(differences, "BYPASSRLS", BypassRls, other.BypassRls);
        return differences;
    }

    private static void Compare(List<string> differences, string name, bool declared, bool actual)
    {
        if (declared != actual)
        {
            differences.Add($"{name} was {(declared ? "declared" : "not declared")} and is {(actual ? "held" : "not held")}");
        }
    }
}

/// <summary>One role as the globals artefact declares it.</summary>
internal sealed record DeclaredRole(string Name, RoleAttributes Attributes);

/// <summary>
/// What a globals artefact declares, and what this agent refused to take from it.
/// </summary>
internal sealed record ClusterGlobals(
    IReadOnlyList<DeclaredRole> Roles,
    IReadOnlyList<string> Memberships,
    IReadOnlyList<string> Refused)
{
    public static ClusterGlobals Empty { get; } = new([], [], []);

    public bool IsEmpty => Roles.Count == 0 && Memberships.Count == 0;
}

/// <summary>
/// A <c>pg_dumpall --globals-only</c> artefact, read rather than executed.
/// <para>
/// <b>The file is never handed to psql as it stands, and that is the whole of
/// this class.</b> It is plain SQL written by somebody else's backup script and
/// fetched out of somebody else's bucket, and three kinds of statement in it must
/// not run on the machine this agent is installed on:
/// </para>
/// <list type="bullet">
/// <item><c>CREATE TABLESPACE … LOCATION '/mnt/fast'</c> makes a directory
/// outside the working directory, which is engineering rule 4 — the one that says
/// we ask for read-only credentials and behave as though we had nothing
/// more.</item>
/// <item><c>ALTER ROLE … SET</c> assigns a server parameter, and some of them
/// name a shared library to load. A drill answers questions about a backup; it
/// does not load code because a file said so.</item>
/// <item><c>ALTER ROLE proofdrill …</c> would rewrite the cluster's own superuser
/// out from under the drill that is running.</item>
/// </list>
/// <para>
/// So the roles, their attributes and their memberships are parsed out, re-emitted
/// as statements this agent wrote, and everything else is reported as refused. A
/// customer reading this repository before running it can see the exact boundary,
/// which is the only form of that promise worth making — <c>protocol/v1/GLOBALS.md</c>.
/// </para>
/// </summary>
internal static class GlobalsDdl
{
    /// <summary>
    /// Membership in these three is not applied, by name. They are PostgreSQL's
    /// own machine-access roles: a member of them can read a file, write a file or
    /// run a program on the host, and an assertion pack can arrive from the
    /// control plane and name a role in its <c>as</c>. <c>ASSERTIONS.md</c> §3
    /// promises the statement cannot reach the machine, and that promise must not
    /// depend on what a customer's globals file happens to contain.
    /// </summary>
    private static readonly HashSet<string> MachineAccess = new(StringComparer.Ordinal)
    {
        "pg_read_server_files",
        "pg_write_server_files",
        "pg_execute_server_program",
    };

    /// <summary>
    /// How many statements one globals artefact may contribute. A cluster with
    /// more roles than this exists; a file with more than this that arrived from a
    /// bucket is worth stopping at and saying so.
    /// </summary>
    public const int StatementCeiling = 500;

    /// <summary>
    /// Reads the artefact. Never throws on strange content: a statement this agent
    /// does not apply is reported, and a file that is not a globals artefact at all
    /// produces no roles and says so — a correction, never a verdict.
    /// </summary>
    /// <param name="sql">The artefact's text.</param>
    /// <param name="reserved">
    /// Role names this cluster already owns — its superuser and the role customer
    /// assertions run as. A globals file that names one of them is not applied to
    /// it, because rewriting the drill's own credentials is not a thing to discover
    /// halfway through a restore.
    /// </param>
    public static ClusterGlobals Read(string sql, IReadOnlyCollection<string> reserved)
    {
        var attributes = new Dictionary<string, RoleAttributes>(StringComparer.Ordinal);
        var order = new List<string>();
        var memberships = new List<string>();
        var refused = new List<string>();

        var tablespaces = 0;
        var settings = 0;
        var unrecognised = 0;
        var conflicting = new List<string>();
        var machine = new List<string>();

        foreach (var statement in Ddl.Split(sql))
        {
            var words = Words(statement);
            if (words.Count == 0)
            {
                continue;
            }

            // The preamble every dump carries — SET client_encoding, and the
            // set_config calls older majors write. They configure the session that
            // would have run the file, and no session here runs it.
            if (Is(words, 0, "SET") || Is(words, 0, "RESET") || Is(words, 0, "SELECT"))
            {
                continue;
            }

            if (Is(words, 0, "CREATE") && Is(words, 1, "TABLESPACE") ||
                Is(words, 0, "ALTER") && Is(words, 1, "TABLESPACE") ||
                Is(words, 0, "DROP") && Is(words, 1, "TABLESPACE"))
            {
                tablespaces++;
                continue;
            }

            if ((Is(words, 0, "CREATE") || Is(words, 0, "ALTER")) &&
                (Is(words, 1, "ROLE") || Is(words, 1, "USER") || Is(words, 1, "GROUP")))
            {
                // ALTER ROLE x SET search_path TO …, its RESET, and the
                // per-database form ALTER ROLE x IN DATABASE d SET … — which is
                // only ever a setting. Not an attribute: it assigns a server
                // parameter, and this agent applies attributes and memberships and
                // nothing else.
                if (Is(words, 3, "SET") || Is(words, 3, "RESET") || Is(words, 3, "IN"))
                {
                    settings++;
                    continue;
                }

                var name = Identifier(words[2]);
                if (name is null)
                {
                    unrecognised++;
                    continue;
                }

                if (reserved.Contains(name, StringComparer.Ordinal) ||
                    name.StartsWith("pg_", StringComparison.Ordinal))
                {
                    conflicting.Add(name);
                    continue;
                }

                if (!attributes.TryGetValue(name, out var current))
                {
                    current = RoleAttributes.Default;
                    order.Add(name);
                }

                attributes[name] = Attributes(words, current);
                continue;
            }

            // A role grant, which in a globals artefact is the only kind there is:
            // a privilege grant carries ON and belongs to a database, not to the
            // cluster.
            if (Is(words, 0, "GRANT") && words.Any(word => string.Equals(word, "TO", StringComparison.OrdinalIgnoreCase))
                && !words.Any(word => string.Equals(word, "ON", StringComparison.OrdinalIgnoreCase)))
            {
                var membership = Membership(words, machine);
                if (membership is null)
                {
                    unrecognised++;
                    continue;
                }

                if (membership.Length > 0)
                {
                    memberships.Add(membership);
                }

                continue;
            }

            unrecognised++;
        }

        if (tablespaces > 0)
        {
            refused.Add(
                $"{tablespaces} tablespace statement(s): a tablespace is a directory on this machine, outside the " +
                "drill's working directory, and this agent does not create one. If the backup's objects live in a " +
                "tablespace, the restore says so on its own.");
        }

        if (settings > 0)
        {
            refused.Add(
                $"{settings} per-role setting(s): ALTER ROLE … SET assigns a server parameter, and some parameters " +
                "name a library for the server to load. Role attributes and memberships are applied; parameters are " +
                "not. An assertion that depends on a role's search_path should name its schema.");
        }

        if (conflicting.Count > 0)
        {
            refused.Add(
                $"{conflicting.Count} role(s) this cluster already owns or reserves: {string.Join(", ", conflicting)}. " +
                "PostgreSQL reserves every name beginning with pg_, and the drill's own roles are not rewritten by a " +
                "file out of a bucket.");
        }

        if (machine.Count > 0)
        {
            refused.Add(
                $"{machine.Count} membership(s) of PostgreSQL's machine-access roles: {string.Join(", ", machine)}. " +
                "A member of those can read a file, write a file or run a program on this machine, and an assertion " +
                "may name a role in its `as`. That boundary does not move because a globals file says so.");
        }

        if (unrecognised > 0)
        {
            refused.Add(
                $"{unrecognised} statement(s) of a kind this agent does not apply. Only role attributes and role " +
                "memberships are taken from a globals artefact; nothing here is executed as it was written.");
        }

        return new ClusterGlobals(
            [.. order.Select(name => new DeclaredRole(name, attributes[name]))],
            memberships,
            refused);
    }

    /// <summary>
    /// The statements this agent will run, in the order they must run in: every
    /// role first, then the memberships between them.
    /// </summary>
    public static IReadOnlyList<string> Statements(ClusterGlobals globals) =>
    [
        .. globals.Roles.Select(role => $"CREATE ROLE {Quote(role.Name)} WITH {role.Attributes.Clause()}"),
        .. globals.Memberships,
    ];

    /// <summary>
    /// The seven attributes, read as whole words so that a base64 password
    /// verifier cannot contribute one. Anything else in the clause — PASSWORD,
    /// VALID UNTIL, CONNECTION LIMIT — is passed over: none of it is readable from
    /// a report, and this cluster has no listener to authenticate anybody against.
    /// </summary>
    private static RoleAttributes Attributes(IReadOnlyList<string> words, RoleAttributes current)
    {
        var attributes = current;

        foreach (var word in words.Skip(3))
        {
            attributes = word.ToUpperInvariant() switch
            {
                "SUPERUSER" => attributes with { Superuser = true },
                "NOSUPERUSER" => attributes with { Superuser = false },
                "INHERIT" => attributes with { Inherit = true },
                "NOINHERIT" => attributes with { Inherit = false },
                "CREATEROLE" => attributes with { CreateRole = true },
                "NOCREATEROLE" => attributes with { CreateRole = false },
                "CREATEDB" => attributes with { CreateDb = true },
                "NOCREATEDB" => attributes with { CreateDb = false },
                "LOGIN" => attributes with { Login = true },
                "NOLOGIN" => attributes with { Login = false },
                "REPLICATION" => attributes with { Replication = true },
                "NOREPLICATION" => attributes with { Replication = false },
                "BYPASSRLS" => attributes with { BypassRls = true },
                "NOBYPASSRLS" => attributes with { BypassRls = false },
                _ => attributes,
            };
        }

        return attributes;
    }

    /// <summary>
    /// One membership, re-emitted rather than repeated. <c>GRANTED BY</c> is
    /// dropped — the grantor here is the drill's own superuser, as it would be for
    /// any restore into a cluster the original's roles never existed in — and the
    /// <c>WITH INHERIT</c> and <c>WITH SET</c> options are kept, because they
    /// decide whether the membership carries privileges and that is a property of
    /// the model being examined.
    /// <para>
    /// Returns an empty string for a membership deliberately not applied, and null
    /// for a statement that could not be read.
    /// </para>
    /// </summary>
    private static string? Membership(IReadOnlyList<string> words, List<string> machine)
    {
        var to = -1;
        var granted = -1;

        for (var index = 1; index < words.Count; index++)
        {
            if (to < 0 && string.Equals(words[index], "TO", StringComparison.OrdinalIgnoreCase))
            {
                to = index;
            }
            else if (granted < 0 && string.Equals(words[index], "GRANTED", StringComparison.OrdinalIgnoreCase)
                     && index + 1 < words.Count
                     && string.Equals(words[index + 1], "BY", StringComparison.OrdinalIgnoreCase))
            {
                granted = index;
            }
        }

        if (to != 2)
        {
            // `GRANT a, b TO c` is legal and pg_dumpall does not write it. A shape
            // this agent has not seen is reported rather than half-read.
            return null;
        }

        var group = Identifier(words[1]);
        if (group is null || to + 1 >= words.Count)
        {
            return null;
        }

        if (MachineAccess.Contains(group))
        {
            machine.Add(group);
            return "";
        }

        var member = Identifier(words[to + 1]);
        if (member is null)
        {
            return null;
        }

        var tail = words
            .Skip(to + 2)
            .Take((granted < 0 ? words.Count : granted) - (to + 2))
            .ToList();

        var options = tail.Count == 0 ? "" : " " + string.Join(' ', tail);
        return $"GRANT {Quote(group)} TO {Quote(member)}{options}";
    }

    /// <summary>
    /// A statement split into words, with quoted runs kept whole. Whitespace is
    /// already collapsed outside quotes by <see cref="Ddl.Split"/>, so this only
    /// has to avoid cutting <c>"Reporting Role"</c> in half — and avoid reading a
    /// word out of a string literal, which is where a password verifier lives.
    /// </summary>
    internal static IReadOnlyList<string> Words(string statement)
    {
        var words = new List<string>();
        var current = new StringBuilder();
        var index = 0;

        while (index < statement.Length)
        {
            var character = statement[index];

            if (character is '\'' or '"')
            {
                var end = Closing(statement, index, character);
                current.Append(statement, index, end - index);
                index = end;
                continue;
            }

            if (character == ' ')
            {
                Flush(words, current);
                index++;
                continue;
            }

            // A comma binds to nothing here: `GRANT a, b TO c` has to come out as
            // words a reader of this list can count.
            if (character == ',')
            {
                Flush(words, current);
                words.Add(",");
                index++;
                continue;
            }

            current.Append(character);
            index++;
        }

        Flush(words, current);
        return words;
    }

    private static void Flush(List<string> words, StringBuilder current)
    {
        if (current.Length > 0)
        {
            words.Add(current.ToString());
            current.Clear();
        }
    }

    private static int Closing(string statement, int start, char delimiter)
    {
        var index = start + 1;
        while (index < statement.Length)
        {
            if (statement[index] != delimiter)
            {
                index++;
                continue;
            }

            if (index + 1 < statement.Length && statement[index + 1] == delimiter)
            {
                index += 2;
                continue;
            }

            return index + 1;
        }

        return statement.Length;
    }

    /// <summary>
    /// An identifier as written, unquoted if it was quoted. Null where the word is
    /// not one — a string literal, or an empty run — because a role name read
    /// wrongly is a role created wrongly.
    /// </summary>
    internal static string? Identifier(string word)
    {
        if (word.Length == 0 || word[0] == '\'')
        {
            return null;
        }

        if (word[0] == '"')
        {
            var name = word.Length > 1 && word[^1] == '"'
                ? word[1..^1].Replace("\"\"", "\"", StringComparison.Ordinal)
                : word[1..];

            return name.Length is 0 or > 63 ? null : name;
        }

        // Unquoted identifiers are folded to lower case by PostgreSQL, and a
        // globals file writes them exactly as the catalogue holds them — so a word
        // with a capital in it is either quoted or is not an identifier.
        return word.AsSpan().ContainsAny(" \t();,") || word.Length > 63 ? null : word;
    }

    private static bool Is(IReadOnlyList<string> words, int index, string keyword) =>
        index < words.Count && string.Equals(words[index], keyword, StringComparison.OrdinalIgnoreCase);

    private static string Quote(string name) =>
        $"\"{name.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
}
