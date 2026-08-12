using System.Text.RegularExpressions;

namespace Proofdrill.Agent;

/// <summary>
/// The statements that make a database <em>that</em> database, in families, plus
/// the one fact about it that is not a statement at all.
/// </summary>
internal sealed record SchemaSet(
    IReadOnlySet<string> Extensions,
    IReadOnlySet<string> Tables,
    IReadOnlySet<string> Sequences,
    IReadOnlySet<string> Constraints,
    IReadOnlySet<string> ForeignKeys,
    IReadOnlySet<string> Functions,
    IReadOnlySet<string> Triggers,
    string? Encoding);

/// <summary>
/// Level 2 — <b>is it still that database?</b> — read out of DDL the same way
/// level 3 reads the guarantees: the artefact's own statements against the
/// restored database's, both written by PostgreSQL's tools, so a difference means
/// a difference rather than a difference in spelling. See
/// <see cref="SecurityDdl"/> for why comparing against the catalogue instead
/// reports every object as changed.
/// <para>
/// What this adds over the restore's exit code is the <em>noun</em>.
/// <c>pg_restore</c> exiting 5 says something failed; this says which foreign key
/// is missing, which is the difference between a report a person can act on and a
/// number they have to take somewhere else.
/// </para>
/// <para>
/// Two families are deliberately not here, because DDL cannot answer them and
/// <see cref="DrillRunner"/> asks the restored database directly instead: whether
/// a sequence came back behind its own data, and which encoding it was restored
/// into.
/// </para>
/// </summary>
internal static partial class SchemaDdl
{
    public static SchemaSet Extract(string ddl)
    {
        var extensions = new SortedSet<string>(StringComparer.Ordinal);
        var tables = new SortedSet<string>(StringComparer.Ordinal);
        var sequences = new SortedSet<string>(StringComparer.Ordinal);
        var constraints = new SortedSet<string>(StringComparer.Ordinal);
        var foreignKeys = new SortedSet<string>(StringComparer.Ordinal);
        var functions = new SortedSet<string>(StringComparer.Ordinal);
        var triggers = new SortedSet<string>(StringComparer.Ordinal);
        string? encoding = null;

        foreach (var statement in Ddl.Split(ddl))
        {
            if (Extension().IsMatch(statement))
            {
                extensions.Add(statement);
            }
            else if (Table().IsMatch(statement) || AlterColumn().IsMatch(statement))
            {
                // The whole CREATE TABLE, not a list of column names: the column
                // types, their NOT NULL, their defaults and any inline CHECK are
                // all inside it, and pg_dump writes a check constraint there
                // rather than as an ALTER TABLE. A comparison of names alone
                // would pass a table whose every column had changed type.
                //
                // The ALTER COLUMN statements belong here too. pg_dump writes a
                // serial column's `SET DEFAULT nextval(...)` and an identity
                // column's `ADD GENERATED` separately from the table only because
                // of restore ordering; a table that came back without its default
                // is a table whose inserts now fail.
                tables.Add(statement);
            }
            else if (Sequence().IsMatch(statement))
            {
                sequences.Add(statement);
            }
            else if (Constraint().IsMatch(statement))
            {
                (ForeignKey().IsMatch(statement) ? foreignKeys : constraints).Add(statement);
            }
            else if (Function().IsMatch(statement))
            {
                functions.Add(statement);
            }
            else if (Trigger().IsMatch(statement))
            {
                triggers.Add(statement);
            }
            else if (ClientEncoding().Match(statement) is { Success: true } match)
            {
                // What pg_dump sets the client encoding to IS the encoding the
                // archive was written in, which is the source database's own. It
                // is the only place a per-database archive records it.
                encoding = match.Groups["encoding"].Value;
            }
        }

        return new SchemaSet(
            extensions, tables, sequences, constraints, foreignKeys, functions, triggers, encoding);
    }

    [GeneratedRegex(@"^CREATE\s+EXTENSION\b", RegexOptions.IgnoreCase)]
    private static partial Regex Extension();

    [GeneratedRegex(@"^CREATE\s+(?:UNLOGGED\s+|GLOBAL\s+|LOCAL\s+|TEMP(?:ORARY)?\s+)*TABLE\b", RegexOptions.IgnoreCase)]
    private static partial Regex Table();

    [GeneratedRegex(@"^ALTER\s+TABLE\b.*\bALTER\s+COLUMN\b", RegexOptions.IgnoreCase)]
    private static partial Regex AlterColumn();

    [GeneratedRegex(@"^(?:CREATE|ALTER)\s+SEQUENCE\b", RegexOptions.IgnoreCase)]
    private static partial Regex Sequence();

    // Primary keys, unique constraints, exclusion constraints and foreign keys
    // are all written by pg_dump as an ALTER TABLE in the post-data section.
    [GeneratedRegex(@"^ALTER\s+TABLE\b.*\bADD\s+CONSTRAINT\b", RegexOptions.IgnoreCase)]
    private static partial Regex Constraint();

    [GeneratedRegex(@"\bFOREIGN\s+KEY\b", RegexOptions.IgnoreCase)]
    private static partial Regex ForeignKey();

    [GeneratedRegex(@"^CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\b", RegexOptions.IgnoreCase)]
    private static partial Regex Function();

    [GeneratedRegex(@"^CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\b", RegexOptions.IgnoreCase)]
    private static partial Regex Trigger();

    [GeneratedRegex(@"^SET\s+client_encoding\s*=\s*'(?<encoding>[^']*)'$", RegexOptions.IgnoreCase)]
    private static partial Regex ClientEncoding();
}
