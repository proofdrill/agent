namespace Proofdrill.Agent.Tests;

/// <summary>
/// The parser fails closed, and these are the tests that keep it that way. A
/// mistyped <c>--dry-run</c> that is quietly ignored runs the drill for real
/// against somebody's machine.
/// </summary>
public class CommandLineTests
{
    [Fact]
    public void Reads_the_subcommand_and_its_options()
    {
        var command = CommandLine.Parse(["drill", "--dump-file", "/work/a.dump", "--dry-run"]);

        Assert.Equal("drill", command.Command);
        Assert.Equal("/work/a.dump", command.Value("--dump-file"));
        Assert.True(command.Has("--dry-run"));
        Assert.False(command.Has("--json"));
    }

    [Fact]
    public void An_unknown_option_is_refused_rather_than_ignored()
    {
        Assert.Throws<UsageException>(() => CommandLine.Parse(["drill", "--dry-runn"]));
    }

    [Fact]
    public void An_option_missing_its_value_is_refused()
    {
        Assert.Throws<UsageException>(() => CommandLine.Parse(["drill", "--dump-file"]));
    }

    [Fact]
    public void No_subcommand_is_refused()
    {
        Assert.Throws<UsageException>(() => CommandLine.Parse([]));
    }

    [Fact]
    public void An_option_where_the_subcommand_should_be_is_refused_by_name()
    {
        var refusal = Assert.Throws<UsageException>(() => CommandLine.Parse(["--dump-file", "/work/a.dump"]));

        Assert.Contains("subcommand", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_required_option_that_is_absent_names_itself()
    {
        var refusal = Assert.Throws<UsageException>(() => CommandLine.Parse(["drill"]).Required("--dump-file"));

        Assert.Contains("--dump-file", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_value_that_should_be_a_whole_number_and_is_not_is_refused()
    {
        Assert.Throws<UsageException>(() =>
            CommandLine.Parse(["drill", "--pg-major", "seventeen"]).Integer("--pg-major"));
    }

    [Fact]
    public void An_absent_number_is_null_rather_than_zero()
    {
        // Zero would be a real value: an RPO window of zero hours means every
        // backup is too old, and a drill would fail for a reason nobody chose.
        Assert.Null(CommandLine.Parse(["drill"]).Number("--rpo-window-hours"));
        Assert.Null(CommandLine.Parse(["drill"]).Integer("--pg-major"));
    }

    [Fact]
    public void A_decimal_point_is_read_and_a_decimal_comma_is_refused()
    {
        // The binary runs with invariant globalization, and a comma read as a
        // thousands separator would turn a window of 1,5 hours into 15.
        Assert.Equal(1.5, CommandLine.Parse(["drill", "--rpo-window-hours", "1.5"]).Number("--rpo-window-hours"));
        Assert.Throws<UsageException>(() =>
            CommandLine.Parse(["drill", "--rpo-window-hours", "1,5"]).Number("--rpo-window-hours"));
    }

    [Fact]
    public void A_path_that_looks_like_an_option_is_still_a_value()
    {
        // Values are taken positionally after their option, so a file whose name
        // begins with a hyphen is not mistaken for an option.
        var command = CommandLine.Parse(["drill", "--dump-file", "--odd-name.dump"]);

        Assert.Equal("--odd-name.dump", command.Value("--dump-file"));
    }
}
