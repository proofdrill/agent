using System.Text.RegularExpressions;

namespace Proofdrill.Agent;

/// <summary>What an artefact says about itself, read without restoring it.</summary>
internal sealed record ArtefactContents(
    IReadOnlyList<string> Tables,
    IReadOnlyList<string> ReferencedRoles,
    bool DeclaresRowLevelSecurity,
    int PolicyCount);

/// <summary>
/// Reads a custom-format archive without restoring it — which is what
/// <c>doctor</c> has to do before the first drill, and what tells a customer up
/// front that half of level 3 will be unattemptable.
/// </summary>
internal static partial class ArtefactInspector
{
    public static async Task<ArtefactContents> ReadAsync(
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
            throw new DrillCannotBeAttemptedException(
                toc.Describe($"reading the table of contents of '{Path.GetFileName(artefact)}'") +
                ". A custom-format archive is what pg_dump writes with -Fc; a plain SQL file is not one.");
        }

        // Every section except the data. The DDL is a few kilobytes where the data
        // may be gigabytes, and doctor must never download or expand rows it has
        // no business reading.
        var ddl = await Processes.RunAsync(
            binaries.PgRestore,
            ["--section", "pre-data", "--section", "post-data", "--file", "-", artefact],
            timeout: TimeSpan.FromMinutes(5),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        var tables = ParseTables(toc.StandardOutput);
        var roles = ParseReferencedRoles(toc.StandardOutput, ddl.StandardOutput);

        return new ArtefactContents(
            tables,
            roles,
            ddl.StandardOutput.Contains("ROW LEVEL SECURITY", StringComparison.Ordinal),
            CreatePolicy().Matches(ddl.StandardOutput).Count);
    }

    /// <summary>
    /// Table entries in the table of contents look like
    /// <c>216; 1259 16389 TABLE public tenant_rows drill</c>.
    /// <para>
    /// The description can be several words — <c>FK CONSTRAINT</c>,
    /// <c>MATERIALIZED VIEW</c>, <c>TABLE DATA</c> — so a purely positional read
    /// of it is wrong. The one case that matters here is the collision between
    /// <c>TABLE</c> and <c>TABLE DATA</c>, and it is handled by name.
    /// </para>
    /// </summary>
    internal static IReadOnlyList<string> ParseTables(string tableOfContents)
    {
        var tables = new List<string>();

        foreach (var line in tableOfContents.Split('\n'))
        {
            var entry = line.Trim();
            if (entry.Length == 0 || entry.StartsWith(';'))
            {
                continue;
            }

            var separator = entry.IndexOf(';');
            if (separator < 0)
            {
                continue;
            }

            var fields = entry[(separator + 1)..]
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (fields.Length >= 5 &&
                string.Equals(fields[2], "TABLE", StringComparison.Ordinal) &&
                !string.Equals(fields[3], "DATA", StringComparison.Ordinal))
            {
                tables.Add($"{fields[3]}.{fields[4]}");
            }
        }

        tables.Sort(StringComparer.Ordinal);
        return tables;
    }

    /// <summary>
    /// Every role name the artefact expects to exist.
    /// <para>
    /// Two sources, because neither is complete on its own. Owners come from the
    /// table of contents, which is structured and reliable — the owner is the
    /// last field of an entry. Grantees exist only in the DDL text, because the
    /// table of contents does not record them, so those are read with a pattern
    /// and the result is **best effort by construction**. That is acceptable
    /// here and nowhere else: this reading informs a warning before the drill,
    /// while the authoritative answer comes after the restore, by comparing what
    /// the artefact referenced against <c>pg_roles</c> in the restored cluster.
    /// </para>
    /// </summary>
    internal static IReadOnlyList<string> ParseReferencedRoles(string tableOfContents, string ddl)
    {
        var roles = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var line in tableOfContents.Split('\n'))
        {
            var entry = line.Trim();
            if (entry.Length == 0 || entry.StartsWith(';'))
            {
                continue;
            }

            var fields = entry.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (fields.Length >= 2)
            {
                Add(roles, fields[^1]);
            }
        }

        foreach (Match match in GrantOrRevoke().Matches(ddl))
        {
            foreach (var name in match.Groups["roles"].Value.Split(','))
            {
                Add(roles, name);
            }
        }

        foreach (Match match in OwnerTo().Matches(ddl))
        {
            Add(roles, match.Groups["role"].Value);
        }

        return [.. roles];
    }

    private static void Add(SortedSet<string> roles, string candidate)
    {
        var name = candidate.Trim().Trim(';').Trim();

        // pg_restore writes a bare hyphen where an entry has no owner.
        if (name is "" or "-")
        {
            return;
        }

        if (name.StartsWith('"') && name.EndsWith('"') && name.Length > 1)
        {
            name = name[1..^1];
        }

        // PUBLIC is the implicit everybody, not a role that has to exist, and
        // reporting it as missing would be a false alarm on every single artefact.
        if (string.Equals(name, "PUBLIC", StringComparison.Ordinal))
        {
            return;
        }

        // Anything with whitespace or a bracket in it is a parse that went wrong,
        // and a wrong role name in a report is worse than a missing one.
        if (name.AsSpan().ContainsAny(" \t()") || name.Length > 63)
        {
            return;
        }

        roles.Add(name);
    }

    [GeneratedRegex(@"^\s*(?:GRANT|REVOKE)\b[^;]*?\b(?:TO|FROM)\s+(?<roles>[^;]+);",
        RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex GrantOrRevoke();

    [GeneratedRegex(@"\bOWNER\s+TO\s+(?<role>[^\s;]+)\s*;", RegexOptions.IgnoreCase)]
    private static partial Regex OwnerTo();

    [GeneratedRegex(@"^\s*CREATE\s+POLICY\b", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex CreatePolicy();
}
