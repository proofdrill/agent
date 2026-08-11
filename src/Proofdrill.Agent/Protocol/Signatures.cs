using System.Security.Cryptography;
using System.Text;

namespace Proofdrill.Agent.Protocol;

/// <summary>
/// The two signatures, and they are different algorithms because they answer
/// different questions. See <c>protocol/v1/PROTOCOL.md</c> §2.
/// </summary>
internal static class Signatures
{
    public const string AgentAlgorithm = "HMAC-SHA256";
    public const string CounterAlgorithm = "ECDSA-P256-SHA256";

    /// <summary>
    /// The agent authenticates itself with the token it was registered with.
    /// Symmetric, and that is the whole reason it is not the evidence: the key is
    /// in the customer's hands, so a report they edited and re-signed would
    /// verify perfectly.
    /// </summary>
    public static string SignAsAgent(byte[] canonical, string token) =>
        Base64Url(HMACSHA256.HashData(Encoding.UTF8.GetBytes(token), canonical));

    public static bool VerifyAgent(byte[] canonical, string token, string signature)
    {
        var expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(token), canonical);
        var given = TryDecode(signature);

        // Fixed-time, because a comparison that returns early tells an attacker
        // how much of a forged signature was right.
        return given is not null && CryptographicOperations.FixedTimeEquals(expected, given);
    }

    /// <summary>
    /// The control plane's attestation: <em>we received exactly this, then</em>.
    /// <para>
    /// Asymmetric so that somebody who trusts neither the customer nor our
    /// software can still check it — with the public key and `openssl`, and
    /// nothing of ours. An HMAC here would be tamper-evident to us and
    /// unverifiable by the only reader who matters.
    /// </para>
    /// </summary>
    public static bool VerifyCounterSignature(byte[] canonical, ECDsa publicKey, string signature)
    {
        var given = TryDecode(signature);
        return given is not null
            && publicKey.VerifyData(canonical, given, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    /// Present so the protocol has one implementation of its own attestation to
    /// test against. The control plane holds the private key; this signs with a
    /// key handed in, which is what a test does and what production never does.
    /// </summary>
    public static string CounterSign(byte[] canonical, ECDsa privateKey) =>
        Base64Url(privateKey.SignData(canonical, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));

    /// <summary>
    /// Base64url without padding, so a signature can sit in a URL, a header or a
    /// file name without a second encoding deciding what happened to the `+`.
    /// </summary>
    public static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[]? TryDecode(string base64Url)
    {
        var padded = base64Url.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };

        return Convert.TryFromBase64String(padded, new byte[padded.Length], out _)
            ? Convert.FromBase64String(padded)
            : null;
    }
}
