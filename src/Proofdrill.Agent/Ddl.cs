using System.Text;

namespace Proofdrill.Agent;

/// <summary>
/// DDL read as statements rather than as text, and the difference between two
/// sets of them.
/// <para>
/// A pattern that reads up to the next semicolon is wrong on exactly the
/// statements levels 2 and 3 exist to compare: a function body carries
/// semicolons inside <c>$$ … $$</c>, and a check constraint or a policy
/// expression can carry one inside a string literal. Truncating is not a false
/// alarm — it is worse. Both sides are truncated at the same wrong place, so two
/// different functions whose first line agrees compare <b>equal</b>, and the
/// report says the database is intact.
/// </para>
/// </summary>
internal static class Ddl
{
    /// <summary>
    /// Splits a script into whole statements: comments dropped, runs of
    /// whitespace <b>outside</b> quoted text collapsed to one space, the
    /// terminating semicolon removed.
    /// <para>
    /// Inside a literal or a quoted identifier every byte is kept, because there
    /// the whitespace is data — <c>'a  b'</c> and <c>'a b'</c> are two different
    /// values and a comparison that could not tell them apart would be reporting
    /// a database it had not read.
    /// </para>
    /// <para>
    /// The escaping understood here is what <c>pg_dump</c> writes and nothing
    /// wider: it sets <c>standard_conforming_strings = on</c>, so a backslash
    /// inside a literal is an ordinary character and the only escape is a
    /// doubled quote.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> Split(string sql)
    {
        var statements = new List<string>();
        var current = new StringBuilder();
        var index = 0;

        while (index < sql.Length)
        {
            var character = sql[index];

            // A comment is whitespace. It is replaced by a space rather than
            // removed, because `SELECT 1--comment\nFROM t` must not become
            // `SELECT 1FROM t`.
            if (character == '-' && Next(sql, index) == '-')
            {
                var end = sql.IndexOf('\n', index);
                index = end < 0 ? sql.Length : end;
                Space(current);
                continue;
            }

            if (character == '/' && Next(sql, index) == '*')
            {
                index = BlockComment(sql, index);
                Space(current);
                continue;
            }

            // A psql meta-command is not SQL, and dropping it is not tidiness.
            // Since 17.6 pg_dump wraps its output in `\restrict` and
            // `\unrestrict` with a token that is RANDOM PER DUMP — kept, it would
            // attach itself to the statement beside it and make that statement
            // differ from its own artefact on every single drill. They are
            // line-oriented and never part of a statement.
            if (character == '\\' && (index == 0 || sql[index - 1] == '\n'))
            {
                var end = sql.IndexOf('\n', index);
                index = end < 0 ? sql.Length : end;
                Space(current);
                continue;
            }

            if (character is '\'' or '"')
            {
                var end = Quoted(sql, index, character);
                current.Append(sql, index, end - index);
                index = end;
                continue;
            }

            if (character == '$' && DollarTag(sql, index) is { } tag)
            {
                var closing = sql.IndexOf(tag, index + tag.Length, StringComparison.Ordinal);
                var end = closing < 0 ? sql.Length : closing + tag.Length;
                current.Append(sql, index, end - index);
                index = end;
                continue;
            }

            if (character == ';')
            {
                Flush(statements, current);
                index++;
                continue;
            }

            if (char.IsWhiteSpace(character))
            {
                Space(current);
                index++;
                continue;
            }

            current.Append(character);
            index++;
        }

        // Whatever is left after the last semicolon. A script that ends without
        // one is malformed, and dropping its final statement silently would hide
        // an object rather than report it.
        Flush(statements, current);
        return statements;
    }

    /// <summary>
    /// What each side has that the other does not, in both directions. A restored
    /// database that <em>gained</em> a statement is as much a finding as one that
    /// lost it: either way it is not the database the artefact describes.
    /// </summary>
    public static (IReadOnlyList<string> Lost, IReadOnlyList<string> Gained) Difference(
        IReadOnlySet<string> declared,
        IReadOnlySet<string> restored) =>
        ([.. declared.Except(restored, StringComparer.Ordinal).Order(StringComparer.Ordinal)],
         [.. restored.Except(declared, StringComparer.Ordinal).Order(StringComparer.Ordinal)]);

    private static char Next(string sql, int index) => index + 1 < sql.Length ? sql[index + 1] : '\0';

    private static void Space(StringBuilder current)
    {
        if (current.Length > 0 && current[^1] != ' ')
        {
            current.Append(' ');
        }
    }

    private static void Flush(List<string> statements, StringBuilder current)
    {
        var statement = current.ToString().Trim();
        if (statement.Length > 0)
        {
            statements.Add(statement);
        }

        current.Clear();
    }

    /// <summary>
    /// The end of a quoted run, doubled delimiters treated as content. An
    /// unterminated quote swallows the rest of the script, which is the honest
    /// reading: everything after it really is inside a literal.
    /// </summary>
    private static int Quoted(string sql, int start, char delimiter)
    {
        var index = start + 1;
        while (index < sql.Length)
        {
            if (sql[index] != delimiter)
            {
                index++;
                continue;
            }

            if (Next(sql, index) == delimiter)
            {
                index += 2;
                continue;
            }

            return index + 1;
        }

        return sql.Length;
    }

    /// <summary>Block comments nest in PostgreSQL, so the depth is counted.</summary>
    private static int BlockComment(string sql, int start)
    {
        var depth = 1;
        var index = start + 2;

        while (index < sql.Length && depth > 0)
        {
            if (sql[index] == '/' && Next(sql, index) == '*')
            {
                depth++;
                index += 2;
            }
            else if (sql[index] == '*' && Next(sql, index) == '/')
            {
                depth--;
                index += 2;
            }
            else
            {
                index++;
            }
        }

        return index;
    }

    /// <summary>
    /// The opening delimiter of a dollar-quoted string, or null.
    /// <para>
    /// A tag follows the rules for an unquoted identifier, so it never starts
    /// with a digit — which is what keeps <c>$1</c> a parameter reference and not
    /// the start of a literal that would swallow the rest of the function.
    /// </para>
    /// </summary>
    private static string? DollarTag(string sql, int start)
    {
        var index = start + 1;

        while (index < sql.Length && (char.IsLetterOrDigit(sql[index]) || sql[index] == '_'))
        {
            if (index == start + 1 && char.IsDigit(sql[index]))
            {
                return null;
            }

            index++;
        }

        return index < sql.Length && sql[index] == '$' ? sql[start..(index + 1)] : null;
    }
}
