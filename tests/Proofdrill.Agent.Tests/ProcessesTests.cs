using System.Diagnostics;

namespace Proofdrill.Agent.Tests;

/// <summary>
/// What a child of this agent inherits, which stopped being a detail the moment
/// one of those children started running SQL somebody else wrote.
/// </summary>
public class ProcessesTests
{
    /// <summary>
    /// The registration token and the storage keys are not passed down. Nothing
    /// below this process needs them — the artefact is fetched over HTTP by the
    /// agent itself, before the cluster exists — and a PostgreSQL server holding
    /// a customer's backup keys in its environment is a fact somebody would have
    /// to explain in a security review, whether or not anything can reach them.
    /// </summary>
    [Fact]
    public void A_child_process_does_not_inherit_the_token_or_the_storage_keys()
    {
        var info = new ProcessStartInfo("postgres");
        info.Environment["PROOFDRILL_TOKEN"] = "rh_agt_secret";
        info.Environment["PROOFDRILL_S3_ACCESS_KEY_ID"] = "AKIAEXAMPLE";
        info.Environment["PROOFDRILL_S3_SECRET_ACCESS_KEY"] = "secret";
        info.Environment["PGHOST"] = "/work/cluster/socket";

        Processes.WithoutSecrets(info);

        Assert.False(info.Environment.ContainsKey("PROOFDRILL_TOKEN"));
        Assert.False(info.Environment.ContainsKey("PROOFDRILL_S3_ACCESS_KEY_ID"));
        Assert.False(info.Environment.ContainsKey("PROOFDRILL_S3_SECRET_ACCESS_KEY"));

        // And nothing else is touched: a cluster whose PGHOST went missing would
        // fail in a way nobody would connect to this.
        Assert.Equal("/work/cluster/socket", info.Environment["PGHOST"]);
    }
}
