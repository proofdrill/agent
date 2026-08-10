namespace Proofdrill.Agent;

/// <summary>
/// Where the server binaries for one major version live, and which majors this
/// image carries.
/// <para>
/// The layout is PGDG's: one directory per major, side by side, which is what
/// makes several of them installable at once. Spike 0 measured the cost at
/// 45 MB per major.
/// </para>
/// </summary>
internal sealed class PostgresBinaries
{
    private const string PgdgRoot = "/usr/lib/postgresql";

    private PostgresBinaries(int major, string binDirectory)
    {
        Major = major;
        BinDirectory = binDirectory;
    }

    public int Major { get; }
    public string BinDirectory { get; }

    public string InitDb => Path.Combine(BinDirectory, "initdb");
    public string PgCtl => Path.Combine(BinDirectory, "pg_ctl");
    public string PgRestore => Path.Combine(BinDirectory, "pg_restore");
    public string Psql => Path.Combine(BinDirectory, "psql");

    /// <summary>Majors present in this image, ascending. Empty outside the image.</summary>
    public static IReadOnlyList<int> AvailableMajors()
    {
        if (!Directory.Exists(PgdgRoot))
        {
            return [];
        }

        var majors = new List<int>();
        foreach (var directory in Directory.EnumerateDirectories(PgdgRoot))
        {
            var name = Path.GetFileName(directory);
            if (int.TryParse(name, out var major) && File.Exists(Path.Combine(directory, "bin", "initdb")))
            {
                majors.Add(major);
            }
        }

        majors.Sort();
        return majors;
    }

    /// <summary>
    /// The binaries for a major, or null when this image does not carry it.
    /// <para>
    /// Returning null rather than falling back to the nearest major is
    /// deliberate. <c>pg_restore</c> from a different major than the one that
    /// wrote the archive is the version gate this product exists to enforce, and
    /// guessing here would produce a restore that half works and a report nobody
    /// should trust.
    /// </para>
    /// </summary>
    public static PostgresBinaries? For(int major)
    {
        var bin = Path.Combine(PgdgRoot, major.ToString(), "bin");
        return File.Exists(Path.Combine(bin, "initdb")) ? new PostgresBinaries(major, bin) : null;
    }
}
