namespace Proofdrill.Agent.Tests;

/// <summary>
/// The doctor downloads nothing, so it checks none of this. What the target's
/// answer buys is the sentence under <c>NOT checked by the doctor</c> — and that
/// list is the half of the output a person acts on, so a wrong sentence there is
/// a wrong instruction rather than a cosmetic one.
/// </summary>
public class GlobalsDeclarationTests
{
    [Fact]
    public void The_four_spellings_are_the_control_planes_own()
    {
        Assert.Equal(GlobalsDeclaration.Included, GlobalsDeclarations.Parse("included"));
        Assert.Equal(GlobalsDeclaration.Separate, GlobalsDeclarations.Parse("separate"));
        Assert.Equal(GlobalsDeclaration.Absent, GlobalsDeclarations.Parse("absent"));

        // The control plane's fourth is "unknown"; the agent's name for the same
        // state is Unstated, because here it also means nobody passed the flag.
        Assert.Equal(GlobalsDeclaration.Unstated, GlobalsDeclarations.Parse("unknown"));
    }

    [Fact]
    public void An_absent_declaration_is_unstated_and_not_an_error()
    {
        // Old control planes do not send it, and nothing auto-updates: an agent
        // that refused to run without it would break every installation that
        // predates the flag.
        Assert.Equal(GlobalsDeclaration.Unstated, GlobalsDeclarations.Parse(null));
    }

    [Fact]
    public void A_spelling_nobody_declared_is_refused_rather_than_read_as_the_default()
    {
        // Falling back to Unstated would turn a typo into the exact sentence the
        // option exists to stop printing, with nothing to tell anybody why.
        var refusal = Assert.Throws<UsageException>(() => GlobalsDeclarations.Parse("Included"));

        Assert.Contains("--globals", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_option_is_accepted_by_the_parser()
    {
        // The parser fails closed, so this is what stands between an agent image
        // and a doctor command from a control plane that knows the flag.
        Assert.Equal("included",
            CommandLine.Parse(["doctor", "--globals", "included"]).Value("--globals"));
    }

    [Fact]
    public void A_target_that_says_the_artefact_carries_them_is_not_told_it_gave_no_pattern()
    {
        var sentence = GlobalsDeclarations.NotLookedFor(GlobalsDeclaration.Included);

        // The defect this replaced: a customer who answered the question one
        // screen earlier read that no answer had been given.
        Assert.DoesNotContain("no globals pattern was given", sentence, StringComparison.Ordinal);
        Assert.Contains("the artefact carries them", sentence, StringComparison.Ordinal);

        // And it still refuses to claim it checked: the table of contents is
        // inside a file the doctor never fetches.
        Assert.Contains("does not download", sentence, StringComparison.Ordinal);
    }

    [Fact]
    public void Each_declaration_says_something_different()
    {
        var sentences = new[]
        {
            GlobalsDeclaration.Unstated,
            GlobalsDeclaration.Included,
            GlobalsDeclaration.Separate,
            GlobalsDeclaration.Absent,
        }.Select(GlobalsDeclarations.NotLookedFor).ToList();

        Assert.Equal(4, sentences.Distinct(StringComparer.Ordinal).Count());
        Assert.All(sentences, sentence =>
            Assert.StartsWith("the cluster globals:", sentence, StringComparison.Ordinal));
    }

    [Fact]
    public void Separate_without_a_pattern_names_the_option_that_would_fix_it()
    {
        // A target contradicting itself: it says a second artefact holds the
        // roles and does not say which object that is.
        var sentence = GlobalsDeclarations.NotLookedFor(GlobalsDeclaration.Separate);

        Assert.Contains("--s3-globals-pattern", sentence, StringComparison.Ordinal);
    }

    [Fact]
    public void Absent_says_the_gap_was_chosen_rather_than_missed()
    {
        var sentence = GlobalsDeclarations.NotLookedFor(GlobalsDeclaration.Absent);

        Assert.Contains("by decision rather than by accident", sentence, StringComparison.Ordinal);
    }
}
