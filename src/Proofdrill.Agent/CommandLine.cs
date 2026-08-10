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
        "--dry-run", "--json", "--help",
    };

    private static readonly HashSet<string> KnownValues = new(StringComparer.Ordinal)
    {
        "--dump-file", "--pg-major", "--rpo-window-hours", "--work-dir",
    };

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
