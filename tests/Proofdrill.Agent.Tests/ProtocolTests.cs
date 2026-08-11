using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Proofdrill.Agent.Protocol;

namespace Proofdrill.Agent.Tests;

public class CanonicalJsonTests
{
    [Fact]
    public void The_order_the_keys_were_written_in_does_not_change_the_bytes()
    {
        var one = CanonicalJson.Bytes(JsonNode.Parse("""{"b":1,"a":2,"c":{"z":3,"y":4}}""")!);
        var other = CanonicalJson.Bytes(JsonNode.Parse("""{"c":{"y":4,"z":3},"a":2,"b":1}""")!);

        Assert.Equal(one, other);
        Assert.Equal("""{"a":2,"b":1,"c":{"y":4,"z":3}}""", Encoding.UTF8.GetString(one));
    }

    [Fact]
    public void Array_order_is_data_and_is_preserved()
    {
        Assert.NotEqual(
            Encoding.UTF8.GetString(CanonicalJson.Bytes(JsonNode.Parse("""["a","b"]""")!)),
            Encoding.UTF8.GetString(CanonicalJson.Bytes(JsonNode.Parse("""["b","a"]""")!)));
    }

    [Fact]
    public void Whitespace_in_the_input_never_reaches_the_output()
    {
        Assert.Equal("""{"a":[1,2]}""",
            Encoding.UTF8.GetString(CanonicalJson.Bytes(JsonNode.Parse("{\n  \"a\": [ 1,\t2 ]\n}")!)));
    }

    // §3 rule 5, and the reason it exists: 0.1 has no single spelling across
    // languages, so a signature over one would fail somewhere, for somebody,
    // with nothing to look at.
    [Fact]
    public void A_fractional_number_is_refused_rather_than_guessed_at()
    {
        var refusal = Assert.Throws<CanonicalisationException>(
            () => CanonicalJson.Bytes(JsonNode.Parse("""{"seconds":0.1}""")!));

        Assert.Contains("integer of the smallest unit", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Only_what_JSON_requires_is_escaped()
    {
        // A plus sign or an ampersand in a table name must not become +: the
        // default encoder does that for HTML safety and another language's
        // implementation would not, so the two would disagree over a byte.
        Assert.Equal("""{"a":"x+y&z<w"}""",
            Encoding.UTF8.GetString(CanonicalJson.Bytes(JsonNode.Parse("""{"a":"x+y&z<w"}""")!)));
    }

    [Fact]
    public void A_quote_and_a_newline_survive_a_round_trip_identically()
    {
        var text = "he said \"no\"\nand left";
        var canonical = CanonicalJson.Bytes(new JsonObject { ["detail"] = text });

        Assert.Equal(text, JsonNode.Parse(Encoding.UTF8.GetString(canonical))!["detail"]!.GetValue<string>());
    }

    [Fact]
    public void Null_is_a_value_and_not_an_absence()
    {
        Assert.Equal("""{"a":null}""",
            Encoding.UTF8.GetString(CanonicalJson.Bytes(JsonNode.Parse("""{"a":null}""")!)));
    }
}

public class SignatureTests
{
    private const string Token = "rh_agt_0123456789abcdef";

    private static JsonObject Envelope() => ReportEnvelope.Build(Report(), new AgentIdentity("agent-1", "1.2.3", "box"));

    private static DrillReport Report() => new(
        DrillReport.CurrentVersion, Outcome.Passed, "1.2.3", 17,
        new DateTimeOffset(2026, 8, 11, 9, 14, 22, TimeSpan.Zero),
        new ArtefactFacts("db.dump", 1234, new DateTimeOffset(2026, 8, 11, 3, 0, 0, TimeSpan.Zero), 6.24, 17),
        new Measurements(6.24, 1.581),
        [new Check("restore_exit_code", Outcome.Passed, "pg_restore exited 0")],
        [new Check("policies_identical", Outcome.Passed, "all 1 policy(s) identical")],
        new Dictionary<string, long>(StringComparer.Ordinal) { ["public.t"] = 20000 },
        ["an observation"],
        ["something not attempted"]);

    // The measurements come out of the drill as fractions of an hour and of a
    // second. If they reached the wire that way the payload could not be
    // canonicalised at all, so this is the test that keeps the two shapes apart.
    [Fact]
    public void An_envelope_built_from_a_real_report_canonicalises()
    {
        var canonical = Encoding.UTF8.GetString(ReportEnvelope.AgentSignedBytes(Envelope()));

        Assert.Contains("\"measuredRpoSeconds\":22464", canonical, StringComparison.Ordinal);
        Assert.Contains("\"measuredRtoMilliseconds\":1581", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void Timestamps_are_RFC_3339_in_UTC_to_the_second()
    {
        Assert.Contains("\"startedAt\":\"2026-08-11T09:14:22Z\"",
            Encoding.UTF8.GetString(ReportEnvelope.AgentSignedBytes(Envelope())), StringComparison.Ordinal);
    }

    [Fact]
    public void The_agent_signature_does_not_cover_itself()
    {
        var envelope = Envelope();
        var before = ReportEnvelope.AgentSignedBytes(envelope);
        ReportEnvelope.Sign(envelope, "agent-1", Token);

        Assert.Equal(before, ReportEnvelope.AgentSignedBytes(envelope));
    }

    [Fact]
    public void The_agent_signature_verifies_with_its_token_and_with_no_other()
    {
        var envelope = ReportEnvelope.Sign(Envelope(), "agent-1", Token);
        var canonical = ReportEnvelope.AgentSignedBytes(envelope);
        var signature = envelope["agentSignature"]!["value"]!.GetValue<string>();

        Assert.True(Signatures.VerifyAgent(canonical, Token, signature));
        Assert.False(Signatures.VerifyAgent(canonical, "rh_agt_somebody_elses_token", signature));
    }

    [Fact]
    public void One_changed_row_count_breaks_the_agent_signature()
    {
        var envelope = ReportEnvelope.Sign(Envelope(), "agent-1", Token);
        var signature = envelope["agentSignature"]!["value"]!.GetValue<string>();

        envelope["report"]!["rowCounts"]!["public.t"] = 19999;

        Assert.False(Signatures.VerifyAgent(ReportEnvelope.AgentSignedBytes(envelope), Token, signature));
    }

    [Fact]
    public void The_counter_signature_verifies_and_says_when_it_was_received()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = Received(ReportEnvelope.Sign(Envelope(), "agent-1", Token), key);

        Assert.True(Signatures.VerifyCounterSignature(
            ReportEnvelope.CounterSignedBytes(envelope), key,
            envelope["receipt"]!["counterSignature"]!["value"]!.GetValue<string>()));
    }

    [Fact]
    public void A_different_key_does_not_verify_the_counter_signature()
    {
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = Received(ReportEnvelope.Sign(Envelope(), "agent-1", Token), signing);

        Assert.False(Signatures.VerifyCounterSignature(
            ReportEnvelope.CounterSignedBytes(envelope), other,
            envelope["receipt"]!["counterSignature"]!["value"]!.GetValue<string>()));
    }

    // §4: the counter-signature covers the agent's signature, which is what makes
    // "this is the report that arrived" a statement rather than an assertion.
    [Fact]
    public void Re_signing_the_report_as_the_agent_breaks_the_counter_signature()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = Received(ReportEnvelope.Sign(Envelope(), "agent-1", Token), key);
        var attested = envelope["receipt"]!["counterSignature"]!["value"]!.GetValue<string>();

        // A customer who holds the agent token edits the report and re-signs it
        // perfectly. The agent signature is valid; the attestation is not.
        envelope["report"]!["outcome"] = Outcome.Passed;
        envelope["report"]!["rowCounts"]!["public.t"] = 1;
        envelope.Remove("agentSignature");
        ReportEnvelope.Sign(envelope, "agent-1", Token);

        Assert.True(Signatures.VerifyAgent(
            ReportEnvelope.AgentSignedBytes(envelope), Token,
            envelope["agentSignature"]!["value"]!.GetValue<string>()));

        Assert.False(Signatures.VerifyCounterSignature(
            ReportEnvelope.CounterSignedBytes(envelope), key, attested));
    }

    [Fact]
    public void Moving_the_received_at_timestamp_breaks_the_counter_signature()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = Received(ReportEnvelope.Sign(Envelope(), "agent-1", Token), key);
        var attested = envelope["receipt"]!["counterSignature"]!["value"]!.GetValue<string>();

        envelope["receipt"]!["receivedAt"] = "2020-01-01T00:00:00Z";

        Assert.False(Signatures.VerifyCounterSignature(
            ReportEnvelope.CounterSignedBytes(envelope), key, attested));
    }

    [Fact]
    public void Base64url_carries_no_padding_and_no_characters_a_url_would_eat()
    {
        var encoded = Signatures.Base64Url([251, 255, 190, 0, 1, 2, 3]);

        Assert.DoesNotContain('=', encoded);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.Equal<byte>([251, 255, 190, 0, 1, 2, 3], Signatures.TryDecode(encoded)!);
    }

    /// <summary>What the control plane will do on receipt, so the protocol has something to test against.</summary>
    private static JsonObject Received(JsonObject envelope, ECDsa key)
    {
        envelope["receipt"] = new JsonObject
        {
            ["receivedAt"] = "2026-08-11T09:15:00Z",
            ["reportId"] = "01J9Z0000000000000000000",
            ["counterSignature"] = new JsonObject
            {
                ["algorithm"] = Signatures.CounterAlgorithm,
                ["keyId"] = "proofdrill-2026",
            },
        };

        envelope["receipt"]!["counterSignature"]!["value"] =
            Signatures.CounterSign(ReportEnvelope.CounterSignedBytes(envelope), key);

        return envelope;
    }
}
