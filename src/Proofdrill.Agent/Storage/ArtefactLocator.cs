using System.Text.RegularExpressions;

namespace Proofdrill.Agent.Storage;

/// <summary>
/// Which object under the prefix is the backup, and which one is the newest.
/// </summary>
internal static partial class ArtefactLocator
{
    public const string AccessKeyVariable = "PROOFDRILL_S3_ACCESS_KEY_ID";
    public const string SecretKeyVariable = "PROOFDRILL_S3_SECRET_ACCESS_KEY";

    /// <summary>
    /// The newest object whose file name matches the pattern.
    /// <para>
    /// Newest by the storage's own <c>LastModified</c> and never by sorting the
    /// names. Backup file names carry dates in whatever format the script that
    /// wrote them chose, and the day somebody switches from <c>2026-08-11</c> to
    /// <c>11-08-2026</c> the sort silently starts drilling a backup from March.
    /// </para>
    /// </summary>
    public static StoredObject? Newest(IEnumerable<StoredObject> objects, string pattern)
    {
        var matcher = Matcher(pattern);

        return objects
            .Where(stored => matcher.IsMatch(stored.Key[(stored.Key.LastIndexOf('/') + 1)..]))
            .OrderByDescending(stored => stored.LastModified)
            .FirstOrDefault();
    }

    /// <summary>
    /// A shell-style glob, because that is what somebody writes when asked for a
    /// file name pattern. <c>*</c> and <c>?</c> only: a full regular expression
    /// in a configuration field is a support conversation waiting to happen.
    /// </summary>
    internal static Regex Matcher(string pattern)
    {
        var translated = string.Concat(pattern.Select(character => character switch
        {
            '*' => ".*",
            '?' => ".",
            _ => Regex.Escape(character.ToString()),
        }));

        return new Regex($"^{translated}$", RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// Credentials come from the environment and from nowhere else.
    /// <para>
    /// Not a preference: a command line is readable by every process on the
    /// machine through <c>ps</c>, and it lands in shell history. These are keys
    /// to somebody's backups, handed to us on the promise that we are careful
    /// with them.
    /// </para>
    /// </summary>
    public static (string AccessKeyId, string SecretAccessKey) Credentials()
    {
        var access = Environment.GetEnvironmentVariable(AccessKeyVariable);
        var secret = Environment.GetEnvironmentVariable(SecretKeyVariable);

        if (string.IsNullOrWhiteSpace(access) || string.IsNullOrWhiteSpace(secret))
        {
            throw new StorageException(
                $"storage credentials are missing. Set {AccessKeyVariable} and {SecretKeyVariable} in the " +
                "environment — they are never accepted on the command line, because a command line is visible " +
                "to every process on the machine.");
        }

        return (access, secret);
    }
}
