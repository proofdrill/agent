namespace Proofdrill.Agent;

internal sealed class UsageException(string message) : Exception(message);

/// <summary>
/// A hand written parser, because the alternative is a dependency on the one
/// artefact whose dependency list is a sales question, and four subcommands do
/// not justify it.
/// <para>
/// It fails closed: an option nobody declared is an error rather than something
/// silently ignored, because a mistyped <c>--dry-run</c> that is quietly dropped
/// runs the drill for real.
/// </para>
/// </summary>
internal sealed class CommandLine
{
    private static readonly HashSet<string> KnownFlags = new(StringComparer.Ordinal)
    {
        "--dry-run", "--json", "--help", "--s3-path-style", "--s3-virtual-host",
        "--envelope", "--canonical-only", "--agent", "--once", "--no-remote-assertions",
    };

    private static readonly HashSet<string> KnownValues = new(StringComparer.Ordinal)
    {
        "--dump-file", "--pg-major", "--rpo-window-hours", "--work-dir",
        "--globals-file", "--s3-globals-pattern",
        "--s3-endpoint", "--s3-bucket", "--s3-prefix", "--s3-pattern", "--s3-region",
        "--report-to", "--agent-id", "--report", "--public-key",
        "--control-plane", "--poll-seconds", "--assertions",
    };

    /// <summary>
    /// Options that exist only to be refused, with a reason. "Unknown option" is
    /// a true answer here and a useless one: somebody who tried to pass a secret
    /// key on the command line will try the next spelling rather than learn why
    /// none of them work.
    /// </summary>
    private static readonly Dictionary<string, string> Refused = new(StringComparer.Ordinal)
    {
        ["--s3-access-key-id"] = Credentials,
        ["--s3-secret-access-key"] = Credentials,
        ["--access-key"] = Credentials,
        ["--secret-key"] = Credentials,
        ["--token"] = "the registration token is read from PROOFDRILL_TOKEN and never from the command line, for " +
                      "the same reason: a command line is readable by every process on the machine.",
    };

    private const string Credentials =
        "storage credentials are never taken from the command line, because a command line is readable by every " +
        "process on the machine and it lands in shell history. Set PROOFDRILL_S3_ACCESS_KEY_ID and " +
        "PROOFDRILL_S3_SECRET_ACCESS_KEY in the environment instead.";

    private CommandLine(string command, Dictionary<string, string> values, HashSet<string> flags)
    {
        Command = command;
        Values = values;
        Flags = flags;
    }

    public string Command { get; }
    public IReadOnlyDictionary<string, string> Values { get; }
    public IReadOnlySet<string> Flags { get; }

    public bool Has(string flag) => Flags.Contains(flag);

    public string? Value(string option) => Values.GetValueOrDefault(option);

    public string Required(string option) =>
        Values.GetValueOrDefault(option) ?? throw new UsageException($"{Command} needs {option}");

    public int? Integer(string option)
    {
        var raw = Values.GetValueOrDefault(option);
        if (raw is null)
        {
            return null;
        }

        return int.TryParse(raw, out var value)
            ? value
            : throw new UsageException($"{option} wants a whole number, and '{raw}' is not one");
    }

    public double? Number(string option)
    {
        var raw = Values.GetValueOrDefault(option);
        if (raw is null)
        {
            return null;
        }

        // Invariant on purpose: this binary runs with InvariantGlobalization, and
        // a decimal comma read as a thousands separator would silently change a
        // recovery window by a factor of ten.
        return double.TryParse(raw, System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var value)
            ? value
            : throw new UsageException($"{option} wants a number with a decimal point, and '{raw}' is not one");
    }

    public static CommandLine Parse(IReadOnlyList<string> arguments)
    {
        if (arguments.Count == 0)
        {
            throw new UsageException("no subcommand given");
        }

        var command = arguments[0];
        if (command.StartsWith('-'))
        {
            throw new UsageException($"expected a subcommand and found the option '{command}'");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);

        for (var index = 1; index < arguments.Count; index++)
        {
            var argument = arguments[index];

            if (Refused.TryGetValue(argument, out var reason))
            {
                throw new UsageException(reason);
            }

            if (KnownFlags.Contains(argument))
            {
                flags.Add(argument);
                continue;
            }

            if (KnownValues.Contains(argument))
            {
                if (index + 1 >= arguments.Count)
                {
                    throw new UsageException($"{argument} needs a value");
                }

                values[argument] = arguments[++index];
                continue;
            }

            throw new UsageException($"unknown option '{argument}'");
        }

        return new CommandLine(command, values, flags);
    }
}
