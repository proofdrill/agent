using System.Text.RegularExpressions;

namespace Proofdrill.Agent.Tests;

/// <summary>
/// What this agent will accept as a customer assertion, and what it refuses
/// before a single byte is downloaded.
/// <para>
/// None of these tests is about stopping dangerous SQL, and that is deliberate:
/// the boundary around a statement is the role it runs as, not a filter over its
/// text — <c>AssertionRunner</c> says so at length. These are about a pack being
/// readable, bounded and producing a report somebody can act on, which is the
/// half that fails silently if nobody checks it.
/// </para>
/// </summary>
public class AssertionPackTests
{
    private const string One = """
        {
          "assertions": [
            {
              "key": "app_role_sees_no_other_tenant",
              "title": "the application role cannot read another tenant's rows",
              "sql": "SELECT count(*) = 0 FROM public.tenant_rows",
              "as": "app_role",
              "settings": { "app.tenant_id": "00000000-0000-0000-0000-000000000000" }
            }
          ]
        }
        """;

    [Fact]
    public void A_pack_is_read_whole()
    {
        var assertion = Assert.Single(AssertionPack.Parse(One).Assertions);

        Assert.Equal("app_role_sees_no_other_tenant", assertion.Key);
        Assert.Equal("app_role", assertion.Role);
        Assert.Equal("SELECT count(*) = 0 FROM public.tenant_rows", assertion.Sql);
        Assert.Equal("app.tenant_id", Assert.Single(assertion.Settings).Key);
    }

    [Fact]
    public void An_assertion_without_a_role_or_settings_is_ordinary()
    {
        var assertion = Assert.Single(AssertionPack.Parse("""
            {"assertions":[{"key":"audit_kept","title":"the audit table came back","sql":"SELECT count(*) > 0 FROM a"}]}
            """).Assertions);

        Assert.Null(assertion.Role);
        Assert.Empty(assertion.Settings);
    }

    // The report's own rule, asserted here because the far end enforces it: a key
    // that fitted the pack and not report.schema.json would produce a document
    // rejected after the drill, with nothing the customer could do about it.
    [Fact]
    public void Every_key_this_pack_accepts_still_fits_the_protocol_after_it_is_prefixed()
    {
        var longest = new string('a', AssertionPack.KeyBudget);
        var pack = AssertionPack.Parse($$"""
            {"assertions":[{"key":"{{longest}}","title":"t","sql":"SELECT true"}]}
            """);

        var key = AssertionRunner.Key(pack.Assertions[0]);

        // The pattern out of protocol/v1/report.schema.json, copied rather than
        // referenced: this is the check that the two documents still agree.
        Assert.Matches(new Regex("^[a-z0-9_]{1,64}$"), key);
        Assert.StartsWith("assertion_", key, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("App_Role", "capitals")]
    [InlineData("9lives", "a leading digit")]
    [InlineData("has-a-hyphen", "a hyphen")]
    [InlineData("", "nothing at all")]
    public void A_key_that_could_not_be_a_line_in_the_report_is_refused(string key, string why)
    {
        var refusal = Refused($$"""
            {"assertions":[{"key":"{{key}}","title":"t","sql":"SELECT true"}]}
            """);

        Assert.Contains("key", refusal.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(why);
    }

    [Fact]
    public void A_key_longer_than_the_budget_is_refused()
    {
        var refusal = Refused($$"""
            {"assertions":[{"key":"{{new string('a', AssertionPack.KeyBudget + 1)}}","title":"t","sql":"SELECT true"}]}
            """);

        Assert.Contains(AssertionPack.KeyBudget.ToString(), refusal.Message, StringComparison.Ordinal);
    }

    // The one field people will ask to make optional. It is not: the person who
    // reads a failed drill is filling in a security questionnaire and cannot read
    // the SQL, so an assertion with no sentence attached fails into silence.
    [Fact]
    public void An_assertion_with_no_title_is_refused_and_the_refusal_says_why()
    {
        var refusal = Refused("""{"assertions":[{"key":"k","sql":"SELECT true"}]}""");

        Assert.Contains("'k'", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("cannot read the SQL", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_assertion_with_no_sql_is_refused()
    {
        Assert.Contains("'sql'", Refused("""{"assertions":[{"key":"k","title":"t"}]}""").Message,
            StringComparison.Ordinal);
    }

    // Refused rather than resolved. First-wins and last-wins are both defensible,
    // and a report carrying the same key twice is a document nobody can read a
    // verdict out of.
    [Fact]
    public void Two_assertions_with_the_same_key_are_refused()
    {
        var refusal = Refused("""
            {"assertions":[
              {"key":"same","title":"a","sql":"SELECT true"},
              {"key":"same","title":"b","sql":"SELECT false"}
            ]}
            """);

        Assert.Contains("two assertions are called 'same'", refusal.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_pack_over_the_ceiling_is_refused_by_the_number()
    {
        var many = string.Join(",", Enumerable.Range(0, AssertionPack.Ceiling + 1)
            .Select(index => $$"""{"key":"a{{index}}","title":"t","sql":"SELECT true"}"""));

        var refusal = Refused($$"""{"assertions":[{{many}}]}""");

        Assert.Contains($"{AssertionPack.Ceiling + 1} assertions", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_statement_longer_than_the_budget_is_refused()
    {
        var refusal = Refused($$"""
            {"assertions":[{"key":"k","title":"t","sql":"{{new string('x', AssertionPack.SqlBudget + 1)}}"}]}
            """);

        Assert.Contains(AssertionPack.SqlBudget.ToString(), refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_setting_name_that_is_not_a_parameter_is_refused()
    {
        var refusal = Refused("""
            {"assertions":[{"key":"k","title":"t","sql":"SELECT true","settings":{"app.tenant_id; DROP":"x"}}]}
            """);

        Assert.Contains("settable parameter name", refusal.Message, StringComparison.Ordinal);
    }

    // Text, like PostgreSQL itself stores it. The reason is the protocol's rule 5
    // wearing a different hat: 42 and "42" would be the same setting written two
    // ways, and only one of them survives a round trip through every language.
    [Fact]
    public void A_setting_that_is_not_a_string_is_refused()
    {
        var refusal = Refused("""
            {"assertions":[{"key":"k","title":"t","sql":"SELECT true","settings":{"work_mem":64}}]}
            """);

        Assert.Contains("must be a string", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_that_is_not_json_is_refused_with_the_parser_saying_where()
    {
        Assert.Contains("not valid JSON", Refused("{ not json").Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_document_with_no_assertions_array_is_refused()
    {
        Assert.Contains("no 'assertions' array", Refused("""{"checks":[]}""").Message, StringComparison.Ordinal);
    }

    // An empty pack is a legitimate thing to have — it is what a target has
    // before anybody writes one — and it must not be an error.
    [Fact]
    public void An_empty_pack_is_valid_and_empty()
    {
        Assert.True(AssertionPack.Parse("""{"assertions":[]}""").IsEmpty);
    }

    [Fact]
    public void A_missing_file_is_named()
    {
        var refusal = Assert.Throws<AssertionPackException>(
            () => AssertionPack.Read(Path.Combine(Path.GetTempPath(), "proofdrill-no-such-pack.json")));

        Assert.Contains("no assertion pack at", refusal.Message, StringComparison.Ordinal);
    }

    private static AssertionPackException Refused(string json) =>
        Assert.Throws<AssertionPackException>(() => AssertionPack.Parse(json));
}
