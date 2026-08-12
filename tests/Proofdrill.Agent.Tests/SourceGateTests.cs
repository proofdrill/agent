namespace Proofdrill.Agent.Tests;

/// <summary>
/// The product was called <c>Rehearsal</c> until 2026-08-09, and the rename
/// touched 223 files in the other repository. Six occurrences survived it in this
/// one — <c>rh_agt_</c>, the old token prefix, in the tests for the signing code
/// — and they survived because nothing here was looking.
/// <para>
/// That is a small thing with a large audience. This repository is public, it is
/// read by somebody deciding whether to run it inside their own network, and the
/// files the leftovers were in are the ones such a reader opens first. A name
/// from a product that no longer exists, in a test about how reports are
/// authenticated, is not a typo to that reader: it is a reason to wonder what
/// else was renamed by hand.
/// </para>
/// <para>
/// The sibling repository has carried a gate like this since M3 for the same
/// reason, and it was written after the same discovery. A rule kept by
/// remembering it is a rule already broken somewhere nobody has looked.
/// </para>
/// </summary>
public sealed class SourceGateTests
{
    /// <summary>
    /// The old product name and the old token prefix. Both are unambiguous:
    /// neither has an innocent reading in a tool that restores database backups,
    /// which is what makes them safe to forbid outright rather than review.
    /// <para>
    /// <c>drill</c> and <c>rehearse</c> are deliberately absent. The product's own
    /// vocabulary is *drill*, and <c>README.md</c> describes what the agent does
    /// as rehearsing a restore — banning the verb would ban the correct word for
    /// the thing this software is.
    /// </para>
    /// </summary>
    private static readonly string[] Forbidden = ["rehearsal", "rh_agt"];

    /// <summary>Files whose subject is the previous name.</summary>
    private static readonly string[] Exempt = ["SourceGateTests.cs"];

    private static readonly string[] Extensions = [".cs", ".sh", ".yml", ".yaml", ".json", ".md"];

    [Fact]
    public void No_file_carries_the_name_this_product_used_to_have()
    {
        var hits = new List<string>();

        foreach (var file in SourceFiles())
        {
            var text = File.ReadAllText(file);
            foreach (var word in Forbidden)
            {
                if (text.Contains(word, StringComparison.OrdinalIgnoreCase))
                {
                    hits.Add($"{Path.GetRelativePath(RepositoryRoot(), file)}: {word}");
                }
            }
        }

        Assert.True(hits.Count == 0,
            "The name this product had before 2026-08-09 is still in the source of a repository that is "
            + "public and is read before it is run:\n" + string.Join("\n", hits));
    }

    /// <summary>
    /// The guard the other repository learned from its schema assertions: a scan
    /// that reaches nothing passes for ever, and reads exactly like a scan that
    /// found nothing. The count is asserted before the absence of hits is allowed
    /// to mean anything.
    /// </summary>
    [Fact]
    public void The_scan_actually_reaches_the_source()
    {
        var files = SourceFiles().ToList();

        Assert.True(files.Count > 20,
            $"Only {files.Count} files were scanned. Either the repository moved or the walk stopped "
            + "finding it, and in both cases the gate above has been passing without looking at anything.");

        Assert.Contains(files, f => f.EndsWith("Program.cs", StringComparison.Ordinal));
        Assert.Contains(files, f => f.EndsWith("verify.sh", StringComparison.Ordinal));
    }

    private static IEnumerable<string> SourceFiles() =>
        Directory.EnumerateFiles(RepositoryRoot(), "*", SearchOption.AllDirectories)
            .Where(f => Extensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                            StringComparison.Ordinal)
                     && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                            StringComparison.Ordinal)
                     && !f.Contains($"{Path.DirectorySeparatorChar}.git{Path.DirectorySeparatorChar}",
                            StringComparison.Ordinal))
            .Where(f => !Exempt.Contains(Path.GetFileName(f), StringComparer.Ordinal));

    /// <summary>
    /// Walks up from the test assembly until it finds the solution file. Not a
    /// relative path with four <c>..</c> in it: that breaks silently the day the
    /// target framework or the configuration changes the output depth, and a
    /// broken root here does not fail — it scans an empty set and passes.
    /// </summary>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Proofdrill.Agent.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "Proofdrill.Agent.slnx was not found above " + AppContext.BaseDirectory);
    }
}
