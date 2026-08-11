using System.Buffers;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Proofdrill.Agent.Protocol;

/// <summary>
/// Raised when a payload cannot be canonicalised. It is deliberately a refusal
/// rather than a best effort: a signature over bytes we are not certain another
/// implementation would produce is worse than no signature, because it fails
/// later, for one customer, with nothing to look at.
/// </summary>
internal sealed class CanonicalisationException(string message) : Exception(message);

/// <summary>
/// The bytes both signatures are taken over. The rules are in
/// <c>protocol/v1/PROTOCOL.md</c> §3 and this is their only implementation on
/// this side.
/// </summary>
internal static class CanonicalJson
{
    private static readonly JsonWriterOptions Options = new()
    {
        Indented = false,
        // Escapes what JSON requires and nothing else. The default encoder also
        // escapes `<`, `>`, `&` and `+` for HTML contexts, which is a sensible
        // default for a web page and a trap for a canonical form: another
        // language's implementation of this protocol would not do it, and the
        // signatures would disagree over a plus sign in a table name.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static byte[] Bytes(JsonNode node)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, Options))
        {
            Write(node, writer);
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static void Write(JsonNode? node, Utf8JsonWriter writer)
    {
        switch (node)
        {
            case null:
                writer.WriteNullValue();
                break;

            case JsonObject o:
                writer.WriteStartObject();
                // Ordinal, at every depth. Any other comparison is culture
                // dependent, and a canonical form that changes with the server's
                // locale is not one.
                foreach (var property in o.OrderBy(property => property.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Key);
                    Write(property.Value, writer);
                }

                writer.WriteEndObject();
                break;

            case JsonArray a:
                writer.WriteStartArray();
                foreach (var item in a)
                {
                    Write(item, writer);
                }

                writer.WriteEndArray();
                break;

            case JsonValue v:
                WriteValue(v, writer);
                break;

            default:
                throw new CanonicalisationException($"unexpected node of type {node.GetType().Name}");
        }
    }

    /// <summary>
    /// A <see cref="JsonValue"/> holds either a parsed <see cref="JsonElement"/>
    /// or the CLR value it was built from, and the two are not interchangeable —
    /// asking a node built from an <c>int</c> for its <c>long</c> fails, and
    /// asking one built from a <c>string</c> for its JsonElement throws.
    /// <para>
    /// Both arrive here, because a report is constructed in code when it is sent
    /// and parsed from a file when it is checked. Rather than a ladder of type
    /// tests that would be one type short forever, both go through the same
    /// parse — so an envelope built in memory and the same envelope read back
    /// from disk cannot canonicalise differently, which is the one property this
    /// class exists to have.
    /// </para>
    /// </summary>
    private static void WriteValue(JsonValue value, Utf8JsonWriter writer)
    {
        using var document = JsonDocument.Parse(value.ToJsonString());
        var element = document.RootElement;

        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;

            case JsonValueKind.True:
            case JsonValueKind.False:
                writer.WriteBooleanValue(element.GetBoolean());
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;

            case JsonValueKind.Number:
                // §3 rule 5. `0.1` has no single spelling across languages, and a
                // signature over a number one implementation renders as `0.1` and
                // another as `0.10000000000000001` fails for a reason nobody
                // finds. Durations are milliseconds, sizes are bytes, ages are
                // seconds — all integers, all by construction rather than by
                // convention.
                if (!element.TryGetInt64(out var integer))
                {
                    throw new CanonicalisationException(
                        $"the payload contains the fractional number {element.GetRawText()}, and a canonical form " +
                        "has no portable spelling for one. Express it as an integer of the smallest unit.");
                }

                writer.WriteNumberValue(integer);
                break;

            default:
                throw new CanonicalisationException($"unexpected value kind {element.ValueKind}");
        }
    }

}
