using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Proofdrill.Agent.Storage;

namespace Proofdrill.Agent.Protocol;

/// <summary>
/// The control plane's published counter-signing keys, fetched over the same
/// outbound connection as everything else.
/// <para>
/// <b>What this is not.</b> It is not a substitute for TLS: a list fetched over a
/// broken connection is as forgeable as the answer it checks. What it adds is
/// that <i>what this agent was told to do</i> is afterwards checkable by somebody
/// who was not there — the same property a report's counter-signature has, and
/// for the same reason.
/// </para>
/// <para>
/// <b>Rotation is why it can refetch.</b> A key id this agent has never seen is
/// the normal, expected consequence of the control plane rotating: one refresh,
/// and if the id is still absent the answer is refused rather than acted on. The
/// list is cached for the life of the process because the alternative — fetching
/// it on every poll — is a request a minute, for ever, to learn nothing.
/// </para>
/// </summary>
internal sealed class PublishedKeys(HttpClient http, Uri origin) : IDisposable
{
    public const string KeyListPath = "/api/v1/keys";

    private readonly Dictionary<string, ECDsa> _keys = new(StringComparer.Ordinal);

    /// <summary>
    /// The key with this id, fetching the list whenever the id is one this
    /// process has not seen — which is what a rotation looks like from here. Not
    /// thread-safe, and does not need to be: one agent polls on one loop.
    /// </summary>
    public async Task<ECDsa> ForAsync(string keyId, CancellationToken cancellationToken)
    {
        if (_keys.TryGetValue(keyId, out var known))
        {
            return known;
        }

        await RefreshAsync(cancellationToken).ConfigureAwait(false);

        return _keys.TryGetValue(keyId, out var fetched)
            ? fetched
            : throw new StorageException(
                $"the control plane signed with key '{keyId}', which it does not publish at "
                + $"{new Uri(origin, KeyListPath)}. Nothing this agent was told can be checked, so nothing "
                + "will be acted on.");
    }

    public void Dispose()
    {
        foreach (var key in _keys.Values)
        {
            key.Dispose();
        }

        _keys.Clear();
    }

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        using var response = await http
            .GetAsync(new Uri(origin, KeyListPath), cancellationToken)
            .ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new StorageException(
                $"the control plane's key list answered HTTP {(int)response.StatusCode}. {body.Trim()}");
        }

        if (JsonNode.Parse(body) is not JsonObject document || document["keys"] is not JsonArray keys)
        {
            throw new StorageException("the control plane's key list is not a key list.");
        }

        foreach (var entry in keys.OfType<JsonObject>())
        {
            var keyId = entry["keyId"]?.GetValue<string>();
            var pem = entry["publicKeyPem"]?.GetValue<string>();

            if (keyId is null || pem is null || _keys.ContainsKey(keyId))
            {
                continue;
            }

            // An algorithm this build cannot check is skipped rather than
            // guessed at — and said out loud, because a key quietly dropped here
            // becomes an unexplained refusal several minutes later.
            if (entry["algorithm"]?.GetValue<string>() is { } algorithm
                && algorithm != Signatures.CounterAlgorithm)
            {
                Console.Error.WriteLine(
                    $"proofdrill: the control plane publishes key '{keyId}' as {algorithm}, which this build "
                    + $"does not verify. It only checks {Signatures.CounterAlgorithm}.");
                continue;
            }

            var key = ECDsa.Create();
            try
            {
                key.ImportFromPem(pem);
                _keys[keyId] = key;
            }
            catch (Exception exception) when (exception is ArgumentException or CryptographicException)
            {
                key.Dispose();
                Console.Error.WriteLine(
                    $"proofdrill: the control plane's key '{keyId}' could not be read: {exception.Message}");
            }
        }
    }
}
