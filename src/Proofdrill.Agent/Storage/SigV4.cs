using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace Proofdrill.Agent.Storage;

/// <summary>
/// AWS Signature Version 4, written here rather than taken from an SDK.
/// <para>
/// The rule in this repository is that a dependency arrives when something
/// cannot be written without it, and signing can. What it buys is worth more
/// than the lines it costs: this artefact is downloaded by people who are
/// deciding whether to hand it the keys to their backup bucket, and "what does
/// it depend on" is the second question they ask. An agent that holds storage
/// credentials and pulls in a large SDK to use them is a longer answer than one
/// that does not.
/// </para>
/// <para>
/// It is also the algorithm every S3-compatible service speaks — MinIO, R2,
/// Backblaze, Wasabi, DigitalOcean Spaces — so there is one signer rather than
/// one SDK per provider.
/// </para>
/// </summary>
internal static class SigV4
{
    private const string Algorithm = "AWS4-HMAC-SHA256";

    /// <summary>The SHA-256 of an empty body, which every request without one carries.</summary>
    public const string EmptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public static void Sign(
        HttpRequestMessage request,
        string accessKeyId,
        string secretAccessKey,
        string region,
        DateTimeOffset now,
        string payloadHash = EmptyBodyHash,
        string service = "s3")
    {
        var uri = request.RequestUri ?? throw new InvalidOperationException("the request has no URI");
        var timestamp = now.ToUniversalTime().ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);
        var date = timestamp[..8];

        request.Headers.Host = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
        request.Headers.TryAddWithoutValidation("x-amz-date", timestamp);
        request.Headers.TryAddWithoutValidation("x-amz-content-sha256", payloadHash);

        var signedHeaders = CanonicalHeaderNames(request);
        var canonicalRequest = string.Join('\n',
            request.Method.Method,
            CanonicalPath(uri),
            CanonicalQuery(uri),
            CanonicalHeaders(request),
            string.Join(';', signedHeaders),
            payloadHash);

        var scope = $"{date}/{region}/{service}/aws4_request";
        var stringToSign = string.Join('\n', Algorithm, timestamp, scope, Hex(Sha256(canonicalRequest)));

        var key = Encoding.UTF8.GetBytes($"AWS4{secretAccessKey}");
        key = HmacSha256(key, date);
        key = HmacSha256(key, region);
        key = HmacSha256(key, service);
        key = HmacSha256(key, "aws4_request");
        var signature = Hex(HmacSha256(key, stringToSign));

        request.Headers.Authorization = new AuthenticationHeaderValue(Algorithm,
            $"Credential={accessKeyId}/{scope}, SignedHeaders={string.Join(';', signedHeaders)}, Signature={signature}");
    }

    /// <summary>
    /// Each path segment decoded and then encoded again, with the slashes left
    /// alone.
    /// <para>
    /// Both halves are load bearing. <see cref="Uri.AbsolutePath"/> hands back a
    /// path that is <em>already</em> percent encoded, so encoding it directly
    /// turns a space into <c>%2520</c> and signs a path the request never asks
    /// for. And <see cref="Uri"/> does not escape everything this algorithm
    /// requires — <c>+</c> and <c>:</c> come through untouched — so taking its
    /// output as it stands is wrong in the other direction.
    /// </para>
    /// <para>
    /// Either mistake produces 403 SignatureDoesNotMatch, which reads as bad
    /// credentials and sends somebody to rotate a key that was never wrong.
    /// </para>
    /// </summary>
    internal static string CanonicalPath(Uri uri)
    {
        var path = uri.AbsolutePath.Length == 0 ? "/" : uri.AbsolutePath;
        return string.Join('/', path.Split('/').Select(segment => Encode(Uri.UnescapeDataString(segment))));
    }

    internal static string CanonicalQuery(Uri uri)
    {
        if (uri.Query.Length <= 1)
        {
            return "";
        }

        var parameters = uri.Query[1..]
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair =>
            {
                var split = pair.Split('=', 2);
                return (Name: Encode(Uri.UnescapeDataString(split[0])),
                        Value: split.Length == 2 ? Encode(Uri.UnescapeDataString(split[1])) : "");
            })
            .OrderBy(pair => pair.Name, StringComparer.Ordinal)
            .ThenBy(pair => pair.Value, StringComparer.Ordinal);

        return string.Join('&', parameters.Select(pair => $"{pair.Name}={pair.Value}"));
    }

    private static IReadOnlyList<string> CanonicalHeaderNames(HttpRequestMessage request) =>
        [.. Headers(request).Select(header => header.Key).Order(StringComparer.Ordinal)];

    private static string CanonicalHeaders(HttpRequestMessage request) =>
        string.Concat(Headers(request)
            .OrderBy(header => header.Key, StringComparer.Ordinal)
            .Select(header => $"{header.Key}:{header.Value}\n"));

    private static IEnumerable<KeyValuePair<string, string>> Headers(HttpRequestMessage request) =>
        request.Headers.Select(header => new KeyValuePair<string, string>(
            header.Key.ToLowerInvariant(),
            string.Join(",", header.Value.Select(value => value.Trim()))));

    /// <summary>
    /// RFC 3986 unreserved characters survive; everything else is percent encoded
    /// in upper case hexadecimal. <see cref="Uri.EscapeDataString"/> agrees on
    /// this today, and it is spelled out because the signature depends on it and
    /// a framework changing its mind here would be silent.
    /// </summary>
    private static string Encode(string value)
    {
        var encoded = new StringBuilder(value.Length);
        foreach (var b in Encoding.UTF8.GetBytes(value))
        {
            var c = (char)b;
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~')
            {
                encoded.Append(c);
            }
            else
            {
                encoded.Append(CultureInfo.InvariantCulture, $"%{b:X2}");
            }
        }

        return encoded.ToString();
    }

    public static string Hex(byte[] value) => Convert.ToHexStringLower(value);

    public static byte[] Sha256(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

    private static byte[] HmacSha256(byte[] key, string value) =>
        HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));
}
