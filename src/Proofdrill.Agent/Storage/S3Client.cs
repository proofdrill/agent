using System.Globalization;
using System.Xml.Linq;

namespace Proofdrill.Agent.Storage;

internal sealed record StoredObject(string Key, long SizeBytes, DateTimeOffset LastModified);

internal sealed record StorageOptions(
    Uri Endpoint,
    string Bucket,
    string Prefix,
    string Pattern,
    string Region,
    bool PathStyle);

/// <summary>
/// Raised when the storage cannot be reached, read, or understood. It is a
/// correction and never a verdict about a backup: a key that is too narrow says
/// nothing at all about whether the artefact behind it would restore.
/// </summary>
internal sealed class StorageException(string message) : Exception(message);

/// <summary>
/// The parts of S3 this agent needs, and no more: list, head, get. Everything
/// else an SDK would bring is surface we would have to defend to somebody
/// deciding whether to give us read access to their backups.
/// </summary>
internal sealed class S3Client(HttpClient http, StorageOptions options, string accessKeyId, string secretAccessKey)
{
    private static readonly XNamespace S3 = "http://s3.amazonaws.com/doc/2006-03-01/";

    /// <summary>
    /// Objects under a prefix. Paged, because a bucket that holds a backup per
    /// day for three years holds more than one page and stopping at the first
    /// would quietly report the wrong newest artefact.
    /// </summary>
    public async Task<IReadOnlyList<StoredObject>> ListAsync(
        string prefix,
        int maxKeys,
        CancellationToken cancellationToken)
    {
        var found = new List<StoredObject>();
        string? continuation = null;

        do
        {
            var query = $"?list-type=2&max-keys={Math.Min(maxKeys, 1000)}";
            if (prefix.Length > 0)
            {
                query += $"&prefix={Uri.EscapeDataString(prefix)}";
            }

            if (continuation is not null)
            {
                query += $"&continuation-token={Uri.EscapeDataString(continuation)}";
            }

            var document = await SendAsync(HttpMethod.Get, "", query, cancellationToken).ConfigureAwait(false);

            foreach (var entry in document.Descendants(S3 + "Contents"))
            {
                var key = entry.Element(S3 + "Key")?.Value;
                var size = entry.Element(S3 + "Size")?.Value;
                var modified = entry.Element(S3 + "LastModified")?.Value;

                if (key is null || size is null || modified is null)
                {
                    continue;
                }

                found.Add(new StoredObject(
                    key,
                    long.Parse(size, CultureInfo.InvariantCulture),
                    DateTimeOffset.Parse(modified, CultureInfo.InvariantCulture).ToUniversalTime()));
            }

            continuation = document.Root?.Element(S3 + "IsTruncated")?.Value == "true"
                ? document.Root?.Element(S3 + "NextContinuationToken")?.Value
                : null;
        }
        while (continuation is not null && found.Count < maxKeys);

        return found;
    }

    /// <summary>
    /// Downloads to a file, refusing before it starts if the disk cannot hold it.
    /// <para>
    /// The order is the point. Checking afterwards, or not at all, is how a tool
    /// fills somebody else's disk — and it is their machine, their production
    /// host quite possibly, and our name on the process that did it.
    /// </para>
    /// </summary>
    public async Task GetAsync(
        StoredObject stored,
        string destination,
        long requiredFreeBytes,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(destination))!;
        Directory.CreateDirectory(directory);

        var available = new DriveInfo(Path.GetPathRoot(directory) ?? "/").AvailableFreeSpace;
        if (available < requiredFreeBytes)
        {
            throw new StorageException(
                $"not enough free disk to download '{stored.Key}': it is {Format(stored.SizeBytes)}, this drill " +
                $"wants {Format(requiredFreeBytes)} free under '{directory}', and {Format(available)} is available. " +
                "Nothing was downloaded.");
        }

        using var request = Request(HttpMethod.Get, stored.Key, "");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        await ThrowIfFailedAsync(response, $"downloading '{stored.Key}'", cancellationToken).ConfigureAwait(false);

        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var file = File.Create(destination);
        await source.CopyToAsync(file, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Metadata for one key. This is the probe that tells a narrow key apart from
    /// an empty prefix: a listing nobody is allowed to make answers 200 with no
    /// contents, and a HEAD on an object that is really there does not.
    /// </summary>
    public async Task<StoredObject?> HeadAsync(string key, CancellationToken cancellationToken)
    {
        using var request = Request(HttpMethod.Head, key, "");
        using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        return new StoredObject(
            key,
            response.Content.Headers.ContentLength ?? 0,
            response.Content.Headers.LastModified?.ToUniversalTime() ?? DateTimeOffset.UnixEpoch);
    }

    private async Task<XDocument> SendAsync(
        HttpMethod method,
        string key,
        string query,
        CancellationToken cancellationToken)
    {
        using var request = Request(method, key, query);
        using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await ThrowIfFailedAsync(response, "listing the bucket", cancellationToken).ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return XDocument.Parse(body);
    }

    private HttpRequestMessage Request(HttpMethod method, string key, string query)
    {
        var request = new HttpRequestMessage(method, BuildUri(key, query));
        SigV4.Sign(request, accessKeyId, secretAccessKey, options.Region, DateTimeOffset.UtcNow);
        return request;
    }

    internal Uri BuildUri(string key, string query)
    {
        var root = options.Endpoint.ToString().TrimEnd('/');
        var encoded = string.Join('/', key.Split('/').Select(Uri.EscapeDataString));

        return options.PathStyle
            ? new Uri($"{root}/{options.Bucket}/{encoded}{query}")
            : new Uri($"{options.Endpoint.Scheme}://{options.Bucket}.{options.Endpoint.Authority}/{encoded}{query}");
    }

    private static async Task ThrowIfFailedAsync(
        HttpResponseMessage response,
        string what,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var code = Code(body);

        // The three that have a cause worth naming, because the generic message
        // sends people to change the wrong thing.
        var hint = code switch
        {
            "SignatureDoesNotMatch" =>
                " The secret key does not match the access key id, or the endpoint's region is not the bucket's.",
            "InvalidAccessKeyId" => " The access key id does not exist at this endpoint.",
            "AccessDenied" => " The key exists and is not allowed to do this.",
            "NoSuchBucket" => " The bucket does not exist at this endpoint. Check the endpoint before the name.",
            _ => "",
        };

        throw new StorageException(
            $"{what} failed: HTTP {(int)response.StatusCode}{(code is null ? "" : $", {code}")}.{hint}");
    }

    private static string? Code(string body)
    {
        try
        {
            return XDocument.Parse(body).Descendants().FirstOrDefault(e => e.Name.LocalName == "Code")?.Value;
        }
        catch (System.Xml.XmlException)
        {
            return null;
        }
    }

    private static string Format(long value) => value switch
    {
        >= 1L << 30 => $"{value / (double)(1L << 30):0.0} GiB",
        >= 1L << 20 => $"{value / (double)(1L << 20):0.0} MiB",
        _ => $"{value / (double)(1L << 10):0.0} KiB",
    };
}
