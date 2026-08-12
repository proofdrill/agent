using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Proofdrill.Agent;
using Proofdrill.Agent.Protocol;
using Proofdrill.Agent.Storage;

namespace Proofdrill.Agent.Tests;

/// <summary>
/// What this agent will and will not act on.
/// <para>
/// <c>JOBS.md</c> v1 shipped with the answer unsigned and said why: a forged job
/// would need TLS to be broken, and there was nowhere to publish the key that
/// would check one. There is now, so the answer is counter-signed — and an agent
/// that accepted an unsigned answer "for compatibility" would have handed anybody
/// who can strip a JSON field the ability to tell a machine inside somebody's
/// perimeter what to do.
/// </para>
/// </summary>
public class JobAnswerTests
{
    private const string AgentId = "0199a4c2-1111-7000-8000-000000000001";
    private const string Token = "rh_agt_0123456789abcdef";

    private static readonly Uri Origin = new("https://control.example");

    private static AgentIdentity Identity() => new(AgentId, "1.4.0", "backup-host");

    /// <summary>
    /// The control plane's side of the wire, built here from the published rules
    /// rather than from its code — which is the same reason the control plane
    /// recomputes this agent's HMAC in its own suite instead of calling ours.
    /// </summary>
    private static string Answer(ECDsa key, string keyId, JsonObject? job)
    {
        var answer = new JsonObject
        {
            ["protocolVersion"] = 1,
            ["job"] = job,
            ["signature"] = new JsonObject
            {
                ["algorithm"] = Signatures.CounterAlgorithm,
                ["keyId"] = keyId,
            },
        };

        answer["signature"]!["value"] = Signatures.CounterSign(JobAnswer.SignedBytes(answer), key);

        // The body IS the canonical bytes, as the endpoint sends them.
        return Encoding.UTF8.GetString(CanonicalJson.Bytes(answer));
    }

    private static JsonObject Job() => new()
    {
        ["id"] = "0199a4c2-2222-7000-8000-000000000009",
        ["target"] = new JsonObject { ["id"] = "0199a4c2-3333-7000-8000-000000000009", ["name"] = "production" },
        ["storage"] = new JsonObject
        {
            ["endpoint"] = "https://s3.eu-central-1.amazonaws.com",
            ["bucket"] = "northwind-backups",
            ["prefix"] = "daily/",
            ["pattern"] = "db-*.dump",
            ["region"] = "eu-central-1",
        },
        ["postgresMajor"] = 17,
        ["rpoWindowHours"] = 24,
        ["leaseExpiresAt"] = "2026-08-11T22:20:00Z",
    };

    private static string KeyList(params (string KeyId, ECDsa Key)[] keys) =>
        new JsonObject
        {
            ["keys"] = new JsonArray(keys.Select(k => (JsonNode)new JsonObject
            {
                ["keyId"] = k.KeyId,
                ["status"] = "active",
                ["algorithm"] = Signatures.CounterAlgorithm,
                ["publicKeyPem"] = k.Key.ExportSubjectPublicKeyInfoPem(),
            }).ToArray()),
        }.ToJsonString();

    /// <summary>A control plane that answers what the test tells it to, and counts who asked.</summary>
    private sealed class Stub : HttpMessageHandler
    {
        public required Func<string> Claim { get; init; }

        public required Func<string> Keys { get; init; }

        public int KeyRequests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path == PublishedKeys.KeyListPath)
            {
                KeyRequests++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(Keys(), Encoding.UTF8, "application/json"),
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(Claim(), Encoding.UTF8, "application/json"),
            });
        }
    }

    private static async Task<(AssignedJob? Job, int KeyRequests)> ClaimAsync(Stub stub)
    {
        using var http = new HttpClient(stub);
        using var keys = new PublishedKeys(http, Origin);
        var controlPlane = new ControlPlane(http, Origin, AgentId, Token, keys);

        var job = await controlPlane.ClaimAsync(Identity(), CancellationToken.None);
        return (job, stub.KeyRequests);
    }

    [Fact]
    public async Task An_answer_carrying_no_signature_is_refused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var unsigned = new JsonObject { ["protocolVersion"] = 1, ["job"] = Job() }.ToJsonString();

        var refusal = await Assert.ThrowsAsync<StorageException>(() => ClaimAsync(new Stub
        {
            Claim = () => unsigned,
            Keys = () => KeyList(("key-2026", key)),
        }));

        // Named, and not silently ignored: an agent that treats a missing
        // signature as "this control plane is older" has a downgrade path.
        Assert.Contains("no counter-signature", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_answer_altered_after_it_was_signed_is_refused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var answer = (JsonObject)JsonNode.Parse(Answer(key, "key-2026", Job()))!;

        // The bucket the agent would have gone to. This is the whole attack the
        // signature exists to make visible.
        answer["job"]!["storage"]!["bucket"] = "somewhere-else";

        var refusal = await Assert.ThrowsAsync<StorageException>(() => ClaimAsync(new Stub
        {
            Claim = () => answer.ToJsonString(),
            Keys = () => KeyList(("key-2026", key)),
        }));

        Assert.Contains("does not verify", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_answer_signed_by_a_key_the_control_plane_does_not_publish_is_refused()
    {
        using var published = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Signed by a key that verifies perfectly and is not on the list. The id
        // is what the list is consulted for, so this is refused for not being
        // published rather than for failing to verify.
        var refusal = await Assert.ThrowsAsync<StorageException>(() => ClaimAsync(new Stub
        {
            Claim = () => Answer(stranger, "key-nobody-published", Job()),
            Keys = () => KeyList(("key-2026", published)),
        }));

        Assert.Contains("key-nobody-published", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_signed_answer_is_checked_once_and_then_read()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var stub = new Stub
        {
            Claim = () => Answer(key, "key-2026", Job()),
            Keys = () => KeyList(("key-2026", key)),
        };

        var (job, requests) = await ClaimAsync(stub);

        Assert.NotNull(job);
        Assert.Equal("production", job.TargetName);
        Assert.Equal("northwind-backups", job.Storage.Bucket);
        Assert.Equal(17, job.PostgresMajor);

        // One fetch for one claim, and the rotation test below shows the second
        // claim adds none: a request a minute for ever would teach nobody
        // anything.
        Assert.Equal(1, requests);
    }

    [Fact]
    public async Task Nothing_to_do_is_signed_too_and_is_still_nothing_to_do()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var (job, _) = await ClaimAsync(new Stub
        {
            Claim = () => Answer(key, "key-2026", null),
            Keys = () => KeyList(("key-2026", key)),
        });

        Assert.Null(job);
    }

    [Fact]
    public async Task A_key_id_this_process_has_never_seen_makes_it_look_at_the_list_again()
    {
        using var previous = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rotated = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // What a rotation looks like from inside somebody's perimeter: the same
        // control plane, signing with an id this agent has never seen. It refetches
        // rather than refusing, and refuses only if the id is still absent.
        var keyId = "key-2026";
        var signer = previous;
        var list = () => KeyList(("key-2026", previous));

        var stub = new Stub
        {
            Claim = () => Answer(signer, keyId, Job()),
            Keys = () => list(),
        };

        using var http = new HttpClient(stub);
        using var keys = new PublishedKeys(http, Origin);
        var controlPlane = new ControlPlane(http, Origin, AgentId, Token, keys);

        Assert.NotNull(await controlPlane.ClaimAsync(Identity(), CancellationToken.None));
        Assert.Equal(1, stub.KeyRequests);

        // Rotated, and the old key stays published — because everything it signed
        // is still evidence.
        keyId = "key-2027";
        signer = rotated;
        list = () => KeyList(("key-2026", previous), ("key-2027", rotated));

        Assert.NotNull(await controlPlane.ClaimAsync(Identity(), CancellationToken.None));
        Assert.Equal(2, stub.KeyRequests);

        // And the key it already knows does not send it back to the list.
        keyId = "key-2026";
        signer = previous;

        Assert.NotNull(await controlPlane.ClaimAsync(Identity(), CancellationToken.None));
        Assert.Equal(2, stub.KeyRequests);
    }

    /// <summary>
    /// The assertion pack is the one field in this protocol that is text the agent
    /// will execute, so the property that matters is not that it arrives — it is
    /// that it cannot arrive altered. Changing a single character of the SQL after
    /// the control plane signed the answer breaks the counter-signature, and the
    /// agent refuses the job rather than running the edited statement.
    /// </summary>
    [Fact]
    public async Task An_assertion_edited_after_the_control_plane_signed_it_is_refused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var job = Job();
        job["assertions"] = Pack("SELECT count(*) = 0 FROM public.tenant_rows");

        var answer = (JsonObject)JsonNode.Parse(Answer(key, "key-2026", job))!;
        answer["job"]!["assertions"]!["assertions"]![0]!["sql"] = "SELECT true";

        var refusal = await Assert.ThrowsAsync<StorageException>(() => ClaimAsync(new Stub
        {
            Claim = () => answer.ToJsonString(),
            Keys = () => KeyList(("key-2026", key)),
        }));

        Assert.Contains("does not verify", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_signed_job_carries_its_assertions_through()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var job = Job();
        job["assertions"] = Pack("SELECT count(*) = 0 FROM public.tenant_rows");

        var (claimed, _) = await ClaimAsync(new Stub
        {
            Claim = () => Answer(key, "key-2026", job),
            Keys = () => KeyList(("key-2026", key)),
        });

        Assert.NotNull(claimed);
        var assertion = Assert.Single(claimed.Assertions.Assertions);
        Assert.Equal("app_role_sees_no_other_tenant", assertion.Key);
        Assert.Equal("app_role", assertion.Role);
    }

    /// <summary>
    /// A job whose pack does not parse is refused as a whole, and the refusal
    /// names it. Drilling the target anyway and dropping the unreadable half would
    /// put a green report in a history whose owner believes their own assertions
    /// are being run.
    /// </summary>
    [Fact]
    public async Task A_job_carrying_a_pack_this_agent_cannot_read_is_refused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var job = Job();
        job["assertions"] = new JsonObject
        {
            ["assertions"] = new JsonArray(new JsonObject
            {
                ["key"] = "no_title_here",
                ["sql"] = "SELECT true",
            }),
        };

        var refusal = await Assert.ThrowsAsync<StorageException>(() => ClaimAsync(new Stub
        {
            Claim = () => Answer(key, "key-2026", job),
            Keys = () => KeyList(("key-2026", key)),
        }));

        Assert.Contains("assertion pack this agent cannot read", refusal.Message, StringComparison.Ordinal);
    }

    private static JsonObject Pack(string sql) => new()
    {
        ["assertions"] = new JsonArray(new JsonObject
        {
            ["key"] = "app_role_sees_no_other_tenant",
            ["title"] = "the application role cannot read another tenant's rows",
            ["sql"] = sql,
            ["as"] = "app_role",
            ["settings"] = new JsonObject { ["app.tenant_id"] = "00000000-0000-0000-0000-000000000000" },
        }),
    };

    [Fact]
    public void The_signed_bytes_are_the_answer_with_only_the_signature_value_removed()
    {
        var answer = (JsonObject)JsonNode.Parse(
            """{"signature":{"algorithm":"ECDSA-P256-SHA256","keyId":"k","value":"zzz"},"job":null,"protocolVersion":1}""")!;

        // Everything else is covered, including the algorithm and the key id: a
        // signature that did not cover the id naming it could be replayed under
        // another key's name.
        Assert.Equal(
            """{"job":null,"protocolVersion":1,"signature":{"algorithm":"ECDSA-P256-SHA256","keyId":"k"}}""",
            Encoding.UTF8.GetString(JobAnswer.SignedBytes(answer)));

        // And the original is untouched — the agent verifies the document it was
        // sent, not a document it edited.
        Assert.Equal("zzz", answer["signature"]!["value"]!.GetValue<string>());
    }
}
