namespace Proofdrill.Agent.Tests;

/// <summary>
/// The measured RPO is the age of the backup, and until 1.0.2 it was the age of
/// the download. These are the three cases that tell those apart.
/// </summary>
public class ArtefactAgeTests
{
    private static DrillOptions Options(DateTimeOffset? writtenAt) =>
        new(ArtefactPath: "artefact.dump",
            PostgresMajor: null,
            DryRun: false,
            WorkRoot: "/work",
            RpoWindowHours: 24,
            ArtefactWrittenAt: writtenAt);

    /// <summary>
    /// A file whose mtime is now, standing for the artefact this agent has just
    /// downloaded. Every drill that fetches from storage has one.
    /// </summary>
    private static FileInfo FreshlyDownloaded()
    {
        var path = Path.Combine(Path.GetTempPath(), $"proofdrill-age-{Guid.NewGuid():N}.dump");
        File.WriteAllText(path, "not a real archive");
        return new FileInfo(path);
    }

    [Fact]
    public void The_age_is_the_storage_timestamp_and_never_the_downloaded_file()
    {
        var file = FreshlyDownloaded();
        try
        {
            var written = DateTimeOffset.UtcNow.AddHours(-1.7);

            // The defect this replaces would answer roughly now, because that is
            // when the download finished. An hour and a half of RPO would be
            // reported as none.
            Assert.Equal(written, DrillRunner.WrittenAt(Options(written), file));
        }
        finally
        {
            file.Delete();
        }
    }

    [Fact]
    public void Without_a_storage_timestamp_the_file_is_the_artefact_and_its_mtime_is_right()
    {
        // --dump-file: somebody pointed at a file on their own machine. Nothing
        // downloaded it, so its mtime is the artefact's own and there is nothing
        // better to use.
        var file = FreshlyDownloaded();
        try
        {
            var expected = new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero);

            Assert.Equal(expected, DrillRunner.WrittenAt(Options(null), file));
        }
        finally
        {
            file.Delete();
        }
    }

    /// <summary>
    /// The failure that matters, stated as the number a report would carry.
    /// A backup job that stopped three weeks ago is the most ordinary disaster
    /// this product exists to notice, and the old behaviour reported it as fresh.
    /// </summary>
    [Fact]
    public void A_backup_that_stopped_three_weeks_ago_is_three_weeks_old_and_not_fresh()
    {
        var file = FreshlyDownloaded();
        try
        {
            var startedAt = DateTimeOffset.UtcNow;
            var written = startedAt.AddDays(-21);

            var age = startedAt - DrillRunner.WrittenAt(Options(written), file);

            Assert.InRange(age.TotalDays, 20.9, 21.1);

            // And the same file read the old way, so the test carries the defect
            // rather than describing it: minutes, against a 24 hour window that
            // would have passed.
            var asTheFileClaims = startedAt - new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero);
            Assert.True(asTheFileClaims.TotalHours < 1);
        }
        finally
        {
            file.Delete();
        }
    }
}
