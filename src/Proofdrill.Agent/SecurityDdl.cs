using System.Text.RegularExpressions;

namespace Proofdrill.Agent;

/// <summary>
/// The statements that carry a database's guarantees, pulled out of DDL and
/// normalised so two sides can be compared.
/// </summary>
internal sealed record GuaranteeSet(
    IReadOnlySet<string> RowLevelSecurity,
    IReadOnlySet<string> Policies,
    IReadOnlySet<string> Grants);

/// <summary>
/// Level 3 compares what the artefact declared against what the restored
/// database actually has — and it does the comparison **DDL against DDL, both
/// written by PostgreSQL's own tools**.
/// <para>
/// The tempting alternative is to read <c>pg_policies</c> and compare it with
/// the archive's text. It does not work: PostgreSQL stores a parsed expression
/// and deparses it on the way out, so
/// <c>tenant_id::text = current_setting('app.tenant_id', true)</c> comes back as
/// <c>((tenant_id)::text = current_setting('app.tenant_id'::text, true))</c> and
/// every policy looks changed. Dumping the restored database with the same
/// <c>pg_dump</c> that wrote the archive puts both sides through the same
/// normalisation, so a difference means a difference.
/// </para>
/// </summary>
internal static partial class SecurityDdl
{
    public static GuaranteeSet Extract(string ddl)
    {
        var rls = new SortedSet<string>(StringComparer.Ordinal);
        var policies = new SortedSet<string>(StringComparer.Ordinal);
        var grants = new SortedSet<string>(StringComparer.Ordinal);

        foreach (Match match in RowLevelSecurity().Matches(ddl))
        {
            rls.Add(Normalise(match.Value));
        }

        foreach (Match match in Policy().Matches(ddl))
        {
            policies.Add(Normalise(match.Value));
        }

        foreach (Match match in Grant().Matches(ddl))
        {
            grants.Add(Normalise(match.Value));
        }

        return new GuaranteeSet(rls, policies, grants);
    }

    /// <summary>
    /// Whitespace collapsed, and the two clauses that are **sets** put in a
    /// canonical order.
    /// <para>
    /// Reordering a clause would hide differences and is never done. Reordering
    /// the contents of a set-valued clause hides nothing, because the order was
    /// never information — and it is not optional, because PostgreSQL stores a
    /// policy's roles as an array of OIDs and prints them in OID order. The
    /// agent creates the missing roles itself, so their OIDs follow the order it
    /// created them in, and the same policy comes back as
    /// <c>TO "Reporting Role", app_role</c> where the artefact said
    /// <c>TO app_role, "Reporting Role"</c>. Without this the product's central
    /// check reports a difference that does not exist — a false alarm on exactly
    /// the assertion nobody else makes.
    /// </para>
    /// </summary>
    private static string Normalise(string statement)
    {
        var collapsed = Whitespace().Replace(statement.Trim(), " ").TrimEnd(';').Trim();

        collapsed = ToClause().Replace(collapsed, match =>
            $"TO {SortList(match.Groups["roles"].Value)}");

        return PrivilegeList().Replace(collapsed, match =>
            $"{match.Groups["verb"].Value} {SortList(match.Groups["privileges"].Value)} ON ");
    }

    private static string SortList(string list) =>
        string.Join(", ", list
            .Split(',')
            .Select(item => item.Trim())
            .Where(item => item.Length > 0)
            .Order(StringComparer.Ordinal));

    /// <summary>
    /// What each side has that the other does not, in both directions. A
    /// restored database that gained a policy is as much a finding as one that
    /// lost it.
    /// </summary>
    public static (IReadOnlyList<string> Lost, IReadOnlyList<string> Gained) Compare(
        IReadOnlySet<string> declared,
        IReadOnlySet<string> restored) =>
        ([.. declared.Except(restored, StringComparer.Ordinal).Order(StringComparer.Ordinal)],
         [.. restored.Except(declared, StringComparer.Ordinal).Order(StringComparer.Ordinal)]);

    [GeneratedRegex(@"^\s*ALTER\s+TABLE\b[^;]*?\bROW\s+LEVEL\s+SECURITY\s*;",
        RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex RowLevelSecurity();

    [GeneratedRegex(@"^\s*CREATE\s+POLICY\b[^;]*;", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex Policy();

    [GeneratedRegex(@"^\s*(?:GRANT|REVOKE)\b[^;]*;", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex Grant();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    // A role list contains no brackets and no string literals, and saying so is
    // what keeps these patterns out of a policy's USING expression — where the
    // word TO can appear inside a quoted value and rewriting it would corrupt the
    // very text being compared. A column level grant, `GRANT SELECT (a, b) ON`,
    // is excluded by the same rule and simply goes uncanonicalised, which can
    // only ever cost a false difference and never hide a real one.
    [GeneratedRegex(@"\bTO\s+(?<roles>[^()']*?)(?=\s+USING\b|\s+WITH\s+CHECK\b|\s+WITH\s+GRANT\s+OPTION\b|$)",
        RegexOptions.IgnoreCase)]
    private static partial Regex ToClause();

    [GeneratedRegex(@"^(?<verb>GRANT|REVOKE)\s+(?<privileges>[^()']*?)\s+ON\s", RegexOptions.IgnoreCase)]
    private static partial Regex PrivilegeList();
}
