using Proofdrill.Agent.Storage;

namespace Proofdrill.Agent;

internal sealed record DoctorReport(
    int ReportVersion,
    bool Ready,
    IReadOnlyList<Check> Checks,
    IReadOnlyList<string> NotAttempted);

/// <summary>
/// What the target says about its cluster globals, as a claim and never as a
/// finding. The doctor downloads nothing, so it cannot check any of this — the
/// declaration exists only so that the sentence it prints about what it did not
/// do is the right sentence.
/// <para>
/// <b>Why it is worth a flag at all.</b> Without one, a customer who answered
/// <i>the roles are inside the artefact</i> on the form one screen earlier reads
/// <i>no globals pattern was given, so nothing was looked for</i> — true to the
/// letter, and it tells them their answer went nowhere. The four values are the
/// control plane's own four, so there is nothing to map and nothing to drift.
/// </para>
/// </summary>
internal enum GlobalsDeclaration
{
    /// <summary>Nobody said, which is also what an older control plane sends.</summary>
    Unstated,

    /// <summary>The artefact carries them. The drill's table of contents settles it.</summary>
    Included,

    /// <summary>A second artefact holds them, named by <c>--s3-globals-pattern</c>.</summary>
    Separate,

    /// <summary>There are none, and level 3's central assertion is out of reach by decision.</summary>
    Absent,
}

internal static class GlobalsDeclarations
{
    /// <summary>
    /// Spelled the way the control plane spells it, lower-cased, and a spelling
    /// nobody declared is refused rather than read as <see
    /// cref="GlobalsDeclaration.Unstated"/>. Falling back to the default would
    /// mean a typo turning into the very sentence this option exists to stop
    /// printing, and the customer would have no way to tell.
    /// </summary>
    public static GlobalsDeclaration Parse(string? value) => value switch
    {
        null => GlobalsDeclaration.Unstated,
        "unknown" => GlobalsDeclaration.Unstated,
        "included" => GlobalsDeclaration.Included,
        "separate" => GlobalsDeclaration.Separate,
        "absent" => GlobalsDeclaration.Absent,
        _ => throw new UsageException(
            $"--globals wants one of included, separate, absent or unknown, and '{value}' is none of them"),
    };

    /// <summary>
    /// What the doctor says about the globals when it looked for nothing, and
    /// <b>why</b> it looked for nothing — which is a different fact in each case.
    /// <para>
    /// This used to be one sentence for all four. It answered a target that had
    /// said <i>the roles are inside the artefact</i> with <i>no globals pattern
    /// was given</i>: true to the letter, and it reads as the answer having been
    /// thrown away, because it had been. The doctor still checks nothing here in
    /// any of these cases — it downloads nothing — and the list this goes into is
    /// the half of the output somebody acts on.
    /// </para>
    /// </summary>
    public static string NotLookedFor(GlobalsDeclaration declared) => declared switch
    {
        GlobalsDeclaration.Included =>
            "the cluster globals: the target says the artefact carries them, so nothing was looked for beside it " +
            "— correctly. Whether they are really in there is a fact inside the artefact, which the doctor does " +
            "not download: the first drill reads the table of contents and settles it. See protocol/v1/GLOBALS.md.",

        GlobalsDeclaration.Absent =>
            "the cluster globals: the target says there are none, so nothing was looked for. Level 3's central " +
            "question — which role is exempt from the policies you wrote — goes unanswered on this database by " +
            "decision rather than by accident, and every report will say so. A pg_dumpall --globals-only artefact " +
            "written beside the backup is what makes it answerable.",

        // Reached only when the pattern is missing, which is a target
        // contradicting itself: it says a second artefact holds them, and does
        // not say which one.
        GlobalsDeclaration.Separate =>
            "the cluster globals: the target says a second artefact holds them and nothing names it, so nothing " +
            "was looked for. Pass --s3-globals-pattern <glob>. Until then this is the one thing the target claims " +
            "that nothing can act on.",

        _ =>
            "the cluster globals: no globals pattern was given, so nothing was looked for. Roles are cluster-wide " +
            "and a per-database pg_dump does not carry them; without a second artefact a drill cannot say which " +
            "role is exempt from the policies you wrote. See protocol/v1/GLOBALS.md.",
    };
}

/// <summary>
/// The first command anybody types, and it restores nothing and downloads
/// nothing. Its job is to find out whether the keys and the configuration work,
/// on the machine the drill will actually run on — which is why it is a
/// subcommand of the same binary and not a separate tool. A diagnosis that runs
/// somewhere else diagnoses somewhere else.
/// </summary>
internal static class DoctorRunner
{
    private const int DiskMultiplier = 3;

    public static async Task<DoctorReport> RunAsync(
        StorageOptions storage,
        int? declaredMajor,
        double? rpoWindowHours,
        string workRoot,
        string? assertionPack,
        string? globalsPattern,
        GlobalsDeclaration declaredGlobals,
        CancellationToken cancellationToken)
    {
        var checks = new List<Check>();
        var notAttempted = new List<string>();

        // First, and before the network: a pack with a typo in it is the cheapest
        // thing here to be wrong about and the most expensive to discover later,
        // because the drill that finds it has already restored the database.
        if (assertionPack is { } path)
        {
            checks.Add(ReadPack(path));
        }
        else
        {
            notAttempted.Add(
                "your own SQL assertions: none were named. Levels 1 to 3 run without them; what only you can ask " +
                "— that a named role sees nothing without a tenant — needs a pack. See protocol/v1/ASSERTIONS.md.");
        }

        var (accessKeyId, secretAccessKey) = ArtefactLocator.Credentials();
        checks.Add(new Check("credentials_present", Outcome.Passed,
            $"{ArtefactLocator.AccessKeyVariable} and {ArtefactLocator.SecretKeyVariable} are set"));

        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        var client = new S3Client(http, storage, accessKeyId, secretAccessKey);

        var listed = await client.ListAsync(storage.Prefix, 1000, cancellationToken).ConfigureAwait(false);
        checks.Add(new Check("storage_reachable", Outcome.Passed,
            $"{storage.Endpoint} answered, bucket '{storage.Bucket}'"));

        // The check §7 says is routinely skipped, and the reason it is skipped is
        // that it looks like it already passed. A list a key is not allowed to
        // make answers 200 with an empty result, not 403 — so an empty listing is
        // "no backup found" and "your key cannot see this" wearing the same face.
        if (listed.Count == 0)
        {
            var anywhere = await client.ListAsync("", 1, cancellationToken).ConfigureAwait(false);

            checks.Add(new Check("key_can_see_the_backups", Outcome.CouldNotAttempt, anywhere.Count > 0
                ? $"nothing is listed under the prefix '{storage.Prefix}', but the bucket is not empty — so the " +
                  "prefix is wrong, or the key is scoped to a different one. This is NOT evidence that the backups " +
                  "are missing."
                : $"nothing is listed under '{storage.Prefix}' and nothing is listed at the root of '{storage.Bucket}' " +
                  "either. That is what an empty bucket looks like AND what a key with no list permission looks " +
                  "like, because S3 answers both with 200 and no contents. Check the key against an object you " +
                  "know is there before believing the bucket is empty."));

            notAttempted.Add("artefact age, size and disk headroom: no artefact was found to measure");
            return new DoctorReport(1, false, checks, notAttempted);
        }

        var artefact = ArtefactLocator.Newest(listed, storage.Pattern);
        if (artefact is null)
        {
            checks.Add(new Check("artefact_found", Outcome.CouldNotAttempt,
                $"{listed.Count} object(s) are under '{storage.Prefix}' and none matches '{storage.Pattern}'. " +
                $"The newest names there are: {string.Join(", ", listed.OrderByDescending(o => o.LastModified).Take(3).Select(o => o.Key))}"));

            notAttempted.Add("artefact age, size and disk headroom: no artefact matched the pattern");
            return new DoctorReport(1, false, checks, notAttempted);
        }

        var age = DateTimeOffset.UtcNow - artefact.LastModified;
        checks.Add(new Check("artefact_found", Outcome.Passed,
            $"{artefact.Key}, {Bytes(artefact.SizeBytes)}, written {age.TotalHours:0.0} h ago"));

        // Now the breadth of the key can be settled rather than guessed: the
        // listing says this object exists, so a HEAD that fails is a key allowed
        // to enumerate and not to read — which produces a drill that fails hours
        // later, having downloaded nothing.
        var head = await client.HeadAsync(artefact.Key, cancellationToken).ConfigureAwait(false);
        checks.Add(head is not null
            ? new Check("key_can_read_the_artefact", Outcome.Passed,
                "the newest artefact was listed and can also be read")
            : new Check("key_can_read_the_artefact", Outcome.Failed,
                $"'{artefact.Key}' is listed and cannot be read. The key may enumerate this bucket and not fetch " +
                "from it, which no drill can work around."));

        // The second artefact, found in the same listing and never downloaded —
        // the doctor's whole value is that it pulls nothing. Whether the file is
        // a globals artefact or something else that matched the pattern is a
        // question only the drill can answer, and this says so rather than
        // implying it checked.
        if (globalsPattern is { Length: > 0 })
        {
            var globals = ArtefactLocator.Newest(listed, globalsPattern);

            checks.Add(globals is not null
                ? new Check("globals_artefact_found", Outcome.Passed,
                    $"{globals.Key}, {Bytes(globals.SizeBytes)}, written " +
                    $"{(DateTimeOffset.UtcNow - globals.LastModified).TotalHours:0.0} h ago. What is inside it is " +
                    "unknown until a drill reads it.")
                : new Check("globals_artefact_found", Outcome.Failed,
                    $"{listed.Count} object(s) are under '{storage.Prefix}' and none matches the globals pattern " +
                    $"'{globalsPattern}'. This says nothing about the backup itself — it means the roles, and " +
                    "therefore level 3's question about which of them is exempt from your own policies, cannot be " +
                    "checked. The pattern is wrong, or the pg_dumpall --globals-only artefact is not being written."));
        }
        else
        {
            // No pattern, so nothing was looked for — and *why* nothing was
            // looked for is a different fact in each case. The old single
            // sentence answered a target that said "the roles are inside the
            // artefact" with "you gave me no pattern", which reads as its answer
            // having been thrown away. It had been.
            notAttempted.Add(GlobalsDeclarations.NotLookedFor(declaredGlobals));
        }

        if (rpoWindowHours is { } window)
        {
            checks.Add(age.TotalHours <= window
                ? new Check("artefact_within_rpo_window", Outcome.Passed,
                    $"{age.TotalHours:0.0} h old, window is {window:0.0} h")
                : new Check("artefact_within_rpo_window", Outcome.Failed,
                    $"{age.TotalHours:0.0} h old, which is outside the declared window of {window:0.0} h. " +
                    "The backups are not being taken as often as somebody has been told they are."));
        }
        else
        {
            notAttempted.Add("artefact_within_rpo_window: no window was declared, so the age is measured and not judged");
        }

        var required = artefact.SizeBytes * DiskMultiplier;
        Directory.CreateDirectory(workRoot);
        var available = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(workRoot)) ?? "/").AvailableFreeSpace;
        checks.Add(available >= required
            ? new Check("disk_headroom", Outcome.Passed,
                $"{Bytes(available)} free under '{workRoot}', and this artefact wants about {Bytes(required)}")
            : new Check("disk_headroom", Outcome.Failed,
                $"only {Bytes(available)} is free under '{workRoot}' and the drill wants about {Bytes(required)} — " +
                $"the compressed artefact is {Bytes(artefact.SizeBytes)}, and it becomes a data directory with its " +
                "indexes rebuilt. Checked now rather than halfway through a restore."));

        var majors = PostgresBinaries.AvailableMajors();
        if (declaredMajor is { } major)
        {
            checks.Add(majors.Contains(major)
                ? new Check("postgres_major_available", Outcome.Passed, $"this image carries PostgreSQL {major}")
                : new Check("postgres_major_available", Outcome.Failed,
                    $"the target declares PostgreSQL {major} and this image carries " +
                    $"[{string.Join(", ", majors)}]. Restoring with a different major is not a restore."));
        }
        else
        {
            notAttempted.Add(
                $"postgres_major_available: no major was declared. This image carries [{string.Join(", ", majors)}], " +
                "and which one the artefact needs is recorded inside it — which the doctor does not open.");
        }

        // Said out loud, because the difference between this and a drill is the
        // whole reason the doctor is safe to run against production storage.
        notAttempted.Add(
            "everything inside the artefact: the doctor does not download it, so the tables it holds, whether it " +
            "carries the cluster roles, and whether it restores at all are all unknown until a drill runs.");

        return new DoctorReport(1, checks.All(check => check.Outcome != Outcome.Failed), checks, notAttempted);
    }

    /// <summary>
    /// The pack, read and bounded but never run: the doctor has no database to
    /// ask, and it says so rather than implying the assertions themselves have
    /// been shown to hold.
    /// </summary>
    private static Check ReadPack(string path)
    {
        try
        {
            var pack = AssertionPack.Read(path);

            return new Check("assertion_pack_readable", Outcome.Passed,
                pack.IsEmpty
                    ? $"'{Path.GetFileName(path)}' is a valid pack and carries no assertions"
                    : $"{pack.Assertions.Count} assertion(s) in '{Path.GetFileName(path)}', each with a title and " +
                      "a statement of a shape this agent will run. Whether they HOLD needs a restored database, " +
                      "which the doctor does not make.");
        }
        catch (AssertionPackException exception)
        {
            return new Check("assertion_pack_readable", Outcome.Failed, exception.Message);
        }
    }

    private static string Bytes(long value) => value switch
    {
        >= 1L << 30 => $"{value / (double)(1L << 30):0.0} GiB",
        >= 1L << 20 => $"{value / (double)(1L << 20):0.0} MiB",
        >= 1L << 10 => $"{value / (double)(1L << 10):0.0} KiB",
        _ => $"{value} B",
    };
}
