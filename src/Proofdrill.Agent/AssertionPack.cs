using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Proofdrill.Agent;

/// <summary>
/// A pack that this agent will not run, and why. Separate from
/// <see cref="UsageException"/> because a pack can arrive from a job as well as
/// from a command line, and the two are refused in different words.
/// </summary>
internal sealed class AssertionPackException(string message) : Exception(message);

/// <summary>
/// One question the customer wants asked of the restored database.
/// <para>
/// <paramref name="Title"/> is not decoration and it is not optional. The person
/// who reads a report is usually not the person who wrote the SQL — they are
/// filling in a security questionnaire and they cannot read a query, which
/// `docs/03` §9 makes a constraint on the report rather than a preference. An
/// assertion that fails has to say what was lost in a sentence, and only its
/// author can write that sentence.
/// </para>
/// <para>
/// <paramref name="Role"/> is what turns a query into a demonstration. Row level
/// security is evaluated against <c>current_user</c>, so "the application role
/// cannot read another tenant's rows" is only asked by becoming that role and
/// trying — asserting it from the catalogue would prove the policy exists, not
/// that it bites. Rule 7 of this repository.
/// </para>
/// </summary>
internal sealed record Assertion(
    string Key,
    string Title,
    string Sql,
    string? Role,
    IReadOnlyList<KeyValuePair<string, string>> Settings);

/// <summary>
/// The customer's own assertions, read from a file or carried by a job.
/// <para>
/// <b>JSON, and no schema language of its own.</b> The agent has no YAML parser
/// and will not acquire one: its dependency list is a sales question, and the
/// people who write these packs already write JSON when they configure
/// everything else in their stack.
/// </para>
/// <para>
/// Every bound here is checked before a single byte is downloaded, because the
/// alternative is discovering a typo after an hour of restore on somebody else's
/// machine. <c>proofdrill doctor --assertions</c> exists for exactly that.
/// </para>
/// </summary>
internal sealed partial record AssertionPack(IReadOnlyList<Assertion> Assertions)
{
    /// <summary>
    /// How many assertions one pack may carry. A ceiling rather than a promise:
    /// each one is a session against a database on the customer's machine, and a
    /// pack of a thousand would turn a drill into a load test of their hardware.
    /// </summary>
    public const int Ceiling = 50;

    /// <summary>
    /// The longest statement accepted. Long enough for a real isolation check
    /// with a CTE in it, short enough that a pack cannot become a program.
    /// </summary>
    public const int SqlBudget = 4096;

    /// <summary>
    /// Keys are bounded at 48 rather than at the protocol's 64 because the report
    /// prefixes them: <c>assertion_</c> is ten characters, and a key that fitted
    /// here and not in <c>report.schema.json</c> would produce a document that
    /// fails validation at the far end, after the drill, with nothing the
    /// customer can do about it.
    /// </summary>
    public const int KeyBudget = 48;

    public static readonly AssertionPack Empty = new([]);

    /// <summary>
    /// Where these came from, in the words the report will use. It is carried
    /// rather than inferred because a pack that arrived from the control plane
    /// and one that was written on the machine are the same JSON and a very
    /// different fact about the drill — and the second is the answer to somebody
    /// whose security review will not allow the first.
    /// </summary>
    public string Origin { get; init; } = "";

    public bool IsEmpty => Assertions.Count == 0;

    /// <summary>Reads a pack from a file the customer wrote.</summary>
    public static AssertionPack Read(string path)
    {
        if (!File.Exists(path))
        {
            throw new AssertionPackException($"no assertion pack at '{path}'");
        }

        return Parse(File.ReadAllText(path));
    }

    public static AssertionPack Parse(string json)
    {
        JsonNode? document;
        try
        {
            document = JsonNode.Parse(json);
        }
        catch (JsonException exception)
        {
            // The parser's own message, because it names the line and the column
            // and this is a file somebody is editing by hand.
            throw new AssertionPackException($"the assertion pack is not valid JSON: {exception.Message}");
        }

        return From(document);
    }

    /// <summary>
    /// The same reading for a file and for a job, deliberately. Two readers would
    /// mean two sets of bounds, and the one that drifted would be the one nobody
    /// runs by hand.
    /// </summary>
    public static AssertionPack From(JsonNode? document)
    {
        if (document is not JsonObject root)
        {
            throw new AssertionPackException(
                "an assertion pack is a JSON object with an 'assertions' array in it");
        }

        if (root["assertions"] is not JsonArray listed)
        {
            throw new AssertionPackException("the assertion pack has no 'assertions' array");
        }

        if (listed.Count > Ceiling)
        {
            throw new AssertionPackException(
                $"the assertion pack carries {listed.Count} assertions and {Ceiling} is the most one drill will " +
                "run. This runs on your machine, and a pack that is really a test suite belongs in your test suite.");
        }

        var assertions = new List<Assertion>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var entry in listed)
        {
            var assertion = One(entry);

            // A duplicate key is refused rather than resolved. Both orders are
            // defensible — first wins, last wins — and a report carrying the same
            // key twice is a document nobody can read a verdict out of.
            if (!seen.Add(assertion.Key))
            {
                throw new AssertionPackException(
                    $"two assertions are called '{assertion.Key}'. Keys name the lines of the report, so they " +
                    "have to be distinct.");
            }

            assertions.Add(assertion);
        }

        return new AssertionPack(assertions);
    }

    private static Assertion One(JsonNode? entry)
    {
        if (entry is not JsonObject assertion)
        {
            throw new AssertionPackException("every entry in 'assertions' is an object");
        }

        var key = Text(assertion, "key")
            ?? throw new AssertionPackException("an assertion has no 'key'");

        if (!KeyShape().IsMatch(key))
        {
            throw new AssertionPackException(
                $"'{key}' is not usable as an assertion key. Lower case letters, digits and underscores, " +
                $"starting with a letter, at most {KeyBudget} characters — it becomes a line in a signed report " +
                "that other software reads.");
        }

        var title = Text(assertion, "title")
            ?? throw new AssertionPackException(
                $"assertion '{key}' has no 'title'. It is the sentence somebody reads when this fails, and they " +
                "cannot read the SQL — write what is lost if this assertion does not hold.");

        if (title.Length > 200)
        {
            throw new AssertionPackException($"the title of '{key}' is longer than 200 characters");
        }

        var sql = Text(assertion, "sql")
            ?? throw new AssertionPackException($"assertion '{key}' has no 'sql'");

        if (sql.Length > SqlBudget)
        {
            throw new AssertionPackException(
                $"the SQL of '{key}' is {sql.Length} characters and {SqlBudget} is the limit");
        }

        var role = Text(assertion, "as");
        if (role is not null && (role.Length > 63 || role.Contains('\0', StringComparison.Ordinal)))
        {
            throw new AssertionPackException($"the role named by '{key}' is not a usable role name");
        }

        return new Assertion(key, title, sql, role, Settings(key, assertion["settings"]));
    }

    /// <summary>
    /// Session settings applied before the statement runs, which is how a policy
    /// reading <c>current_setting('app.tenant_id')</c> is put in front of a tenant
    /// that does not exist and asked what it can see.
    /// <para>
    /// Names are checked against the shape PostgreSQL allows and values are not
    /// checked at all: they are applied through <c>set_config</c> as literals, so
    /// the value is data on the wire and never syntax.
    /// </para>
    /// </summary>
    private static IReadOnlyList<KeyValuePair<string, string>> Settings(string key, JsonNode? node)
    {
        if (node is null)
        {
            return [];
        }

        if (node is not JsonObject settings)
        {
            throw new AssertionPackException($"the 'settings' of '{key}' is an object of name to value");
        }

        if (settings.Count > 10)
        {
            throw new AssertionPackException($"assertion '{key}' sets more than ten session settings");
        }

        var applied = new List<KeyValuePair<string, string>>();

        foreach (var (name, value) in settings)
        {
            if (!SettingName().IsMatch(name))
            {
                throw new AssertionPackException(
                    $"'{name}' in '{key}' is not a settable parameter name. A custom one looks like " +
                    "'app.tenant_id'.");
            }

            if (value is not JsonValue scalar || scalar.GetValueKind() is not JsonValueKind.String)
            {
                // Strings only, and the reason is the same one the protocol gives
                // for having no floating point in a signed payload: a number
                // written by one language and read by another does not have one
                // spelling, and set_config takes text anyway.
                throw new AssertionPackException(
                    $"the setting '{name}' in '{key}' must be a string. PostgreSQL stores every setting as text, " +
                    "so '42' and 42 would be the same value written two ways.");
            }

            var text = scalar.GetValue<string>();
            if (text.Length > 200)
            {
                throw new AssertionPackException($"the setting '{name}' in '{key}' is longer than 200 characters");
            }

            applied.Add(new KeyValuePair<string, string>(name, text));
        }

        return applied;
    }

    private static string? Text(JsonObject assertion, string field) =>
        assertion[field] is JsonValue value && value.GetValueKind() is JsonValueKind.String
            ? value.GetValue<string>() is { Length: > 0 } text ? text : null
            : null;

    [GeneratedRegex(@"^[a-z][a-z0-9_]{0,47}$")]
    private static partial Regex KeyShape();

    // A custom parameter is `class.name`; a built-in one is a bare name. Both are
    // allowed, because `statement_timeout` is a legitimate thing to set on an
    // assertion that walks a large table.
    [GeneratedRegex(@"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$")]
    private static partial Regex SettingName();
}
