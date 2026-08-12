using System.Diagnostics;

namespace Proofdrill.Agent;

/// <summary>
/// A PostgreSQL cluster created for one drill and destroyed at the end of it,
/// running as a child process of this agent.
/// <para>
/// It listens on a unix socket inside its own working directory and on nothing
/// else: <c>-h ""</c> means no TCP listener exists at all, so nothing this agent
/// starts is reachable from the host, from the customer's network, or from us.
/// Spike 0 asserts that positively rather than reading it off a configuration
/// file.
/// </para>
/// </summary>
internal sealed class ThrowawayCluster : IAsyncDisposable
{
    // A unix socket path is capped near 107 bytes by the kernel, and PostgreSQL
    // appends `/.s.PGSQL.5432` to whatever directory it is given. Exceeding it
    // produces a failure to bind that names neither the limit nor the path.
    private const int SocketPathBudget = 107 - 20;

    // ASCII unit separator, built from its code point rather than typed. A
    // control character sitting invisibly in source is unreadable in a diff, and
    // this repository is read before it is run.
    private static readonly string Separator = new string((char)31, 1);

    private readonly PostgresBinaries _binaries;
    private readonly string _root;
    private readonly System.Text.StringBuilder _log = new();
    private Process? _postmaster;
    private bool _disposed;

    public ThrowawayCluster(PostgresBinaries binaries, string workRoot)
    {
        _binaries = binaries;
        _root = Path.Combine(workRoot, "cluster");
        DataDirectory = Path.Combine(_root, "pgdata");
        SocketDirectory = Path.Combine(_root, "socket");

        if (SocketDirectory.Length > SocketPathBudget)
        {
            throw new DrillCannotBeAttemptedException(
                $"the working directory is too deep for a unix socket: '{SocketDirectory}' is " +
                $"{SocketDirectory.Length} characters and the kernel allows about {SocketPathBudget}. " +
                "Run the agent with a shorter work directory.");
        }
    }

    public string DataDirectory { get; }
    public string SocketDirectory { get; }
    public static string SuperUser => "proofdrill";

    /// <summary>
    /// Creates the cluster. <c>--no-sync</c> is safe and honest here: this data
    /// directory is deleted at the end of the drill, and initdb sits OUTSIDE the
    /// window reported as measured RTO. The server itself runs with durability at
    /// its defaults, because a restore timed with fsync off produces a recovery
    /// time faster than the real one — and on a number a customer owes to a third
    /// party, optimistic is the worst direction to be wrong in.
    /// <para>
    /// The <paramref name="encoding"/> is the artefact's own, not ours. Restoring
    /// a LATIN1 archive into a UTF8 cluster works — the server converts on the
    /// way in — and produces a database whose every text column has been through
    /// a conversion the original never had. Level 2 asks whether this is still
    /// that database, so the answer must not be "no, because of a default we
    /// chose".
    /// </para>
    /// </summary>
    public async Task CreateAsync(string encoding, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(SocketDirectory);

        var result = await Processes.RunAsync(
            _binaries.InitDb,
            [
                "--pgdata", DataDirectory,
                "--username", SuperUser,
                "--auth", "trust",
                "--encoding", encoding,
                // The locale is ours and cannot be otherwise: a per-database
                // archive does not record the original's collation. Every report
                // says so under what it did not check, because index ordering
                // over text follows C rules here whatever production used.
                "--locale", "C",
                "--no-sync",
            ],
            timeout: TimeSpan.FromMinutes(5),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            throw new DrillCannotBeAttemptedException(result.Describe("initdb"));
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var info = new ProcessStartInfo(Path.Combine(_binaries.BinDirectory, "postgres"))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        info.ArgumentList.Add("-D");
        info.ArgumentList.Add(DataDirectory);
        info.ArgumentList.Add("-k");
        info.ArgumentList.Add(SocketDirectory);
        // The empty value is the argument that matters: no TCP listener at all.
        info.ArgumentList.Add("-h");
        info.ArgumentList.Add("");

        // The server must not inherit the registration token or the storage keys.
        // It is about to run SQL that the customer wrote and that may have
        // travelled from the control plane, and an environment is readable from
        // inside a database by anything privileged enough to read it.
        Processes.WithoutSecrets(info);

        _postmaster = Process.Start(info)
            ?? throw new DrillCannotBeAttemptedException("the throwaway PostgreSQL would not start");

        // Drained continuously, and that is not tidiness. PostgreSQL writes its
        // log to stderr; a redirected pipe that nobody reads fills at 64 KB and
        // then the server BLOCKS on its own logging. The drill would hang with no
        // error anywhere, which is the worst failure shape available to a tool
        // running unattended on somebody else's machine.
        _postmaster.OutputDataReceived += (_, e) => { if (e.Data is not null) _log.AppendLine(e.Data); };
        _postmaster.ErrorDataReceived += (_, e) => { if (e.Data is not null) _log.AppendLine(e.Data); };
        _postmaster.BeginOutputReadLine();
        _postmaster.BeginErrorReadLine();

        // Readiness is asked of the server rather than slept for. A fixed delay is
        // either too short on a loaded machine — which is somebody else's machine —
        // or wasted on every drill for ever.
        var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (_postmaster.HasExited)
            {
                throw new DrillCannotBeAttemptedException(
                    $"the throwaway PostgreSQL exited {_postmaster.ExitCode} while starting: " +
                    _log.ToString().Trim().ReplaceLineEndings(" "));
            }

            var probe = await QueryAsync("postgres", "SELECT 1", cancellationToken, TimeSpan.FromSeconds(5))
                .ConfigureAwait(false);
            if (probe.Succeeded)
            {
                return;
            }

            await Task.Delay(200, cancellationToken).ConfigureAwait(false);
        }

        throw new DrillCannotBeAttemptedException("the throwaway PostgreSQL did not become ready within 60 s");
    }

    /// <summary>Runs one statement and returns its rows, fields separated by <see cref="Separator"/>.</summary>
    public Task<ProcessResult> QueryAsync(
        string database,
        string sql,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null) =>
        Processes.RunAsync(
            _binaries.Psql,
            [
                "--quiet", "--tuples-only", "--no-align",
                // A field separator that can appear inside data produces a parse
                // that is wrong rather than absent, which is the worse failure.
                "--field-separator", Separator,
                "--variable", "ON_ERROR_STOP=1",
                "--dbname", database,
                "--command", sql,
            ],
            Environment(),
            timeout ?? TimeSpan.FromMinutes(2),
            cancellationToken);

    /// <summary>
    /// Runs a statement <b>as</b> another role, by connecting as that role.
    /// <para>
    /// Not <c>SET ROLE</c> from our own session, and the difference is the whole
    /// boundary around a customer's assertion: a session whose session role is
    /// the superuser can <c>RESET ROLE</c> and take it back, so anything running
    /// under <c>SET ROLE</c> is limited by convention. Connecting as the role
    /// makes the server hold the limit instead — trust authentication over the
    /// private socket is what allows it without a password.
    /// </para>
    /// <para>
    /// Errors come back verbose so that the SQLSTATE can be read out of them.
    /// Rule 8: the message is localised and quotes data, the code is neither.
    /// </para>
    /// </summary>
    public Task<ProcessResult> QueryAsAsync(
        string user,
        string database,
        string sql,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var environment = new Dictionary<string, string>(Environment(), StringComparer.Ordinal)
        {
            ["PGUSER"] = user,
        };

        return Processes.RunAsync(
            _binaries.Psql,
            [
                "--quiet", "--tuples-only", "--no-align",
                "--field-separator", Separator,
                "--variable", "ON_ERROR_STOP=1",
                "--variable", "VERBOSITY=verbose",
                "--dbname", database,
                "--command", sql,
            ],
            environment,
            timeout,
            cancellationToken);
    }

    public static IEnumerable<string[]> Rows(ProcessResult result) =>
        result.StandardOutput
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split(Separator));

    /// <summary>
    /// Restores the artefact **faithfully**: no <c>--no-owner</c>, no
    /// <c>--no-privileges</c>.
    /// <para>
    /// Those two flags are the usual advice and they are exactly wrong here. They
    /// suppress the ownership and grant statements, which means they suppress the
    /// failure spike 0 found — a dump whose roles do not exist restores silently
    /// clean, and the report would say the guarantees survived when the entire
    /// authorization model did not travel. We restore what the artefact actually
    /// contains and report what happened to it.
    /// </para>
    /// </summary>
    public Task<ProcessResult> RestoreAsync(
        string artefact,
        string database,
        CancellationToken cancellationToken,
        TimeSpan timeout) =>
        Processes.RunAsync(
            _binaries.PgRestore,
            ["--dbname", database, artefact],
            Environment(),
            timeout,
            cancellationToken);

    public IReadOnlyDictionary<string, string> Environment() => new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["PGHOST"] = SocketDirectory,
        ["PGUSER"] = SuperUser,
        ["PGDATABASE"] = "postgres",
        // A drill runs on a machine nobody is watching, so an interactive
        // password prompt would not fail — it would hang, and a ~/.pgpass
        // belonging to whoever runs the container is not ours to read. Trust
        // authentication over a private socket is what makes that safe.
        //
        // A path that does not exist, and NOT /dev/null: psql warns that the
        // password file is not a plain file, on every connection. That warning is
        // in the standard error this agent now shows a customer when their own
        // assertion fails to run, where it reads as part of the failure.
        ["PGPASSFILE"] = Path.Combine(_root, "no-password-file"),
    };

    /// <summary>
    /// Stops the server and removes everything the drill created — on success, on
    /// failure, on an exception and on a signal. This is engineering rule 10, and
    /// it is the difference between a tool people keep running and one that fills
    /// a disk on a Sunday night.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_postmaster is { } postmaster)
        {
            try
            {
                // pg_ctl stops the backends too. Killing the postmaster directly
                // leaves its children behind, which is the orphan this rule exists
                // to prevent.
                await Processes.RunAsync(
                    _binaries.PgCtl,
                    ["--pgdata", DataDirectory, "--mode", "immediate", "--wait", "stop"],
                    timeout: TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Fall through to the blunt instrument below.
            }

            try
            {
                if (!postmaster.HasExited)
                {
                    postmaster.Kill(entireProcessTree: true);
                    postmaster.WaitForExit(10_000);
                }
            }
            catch (Exception)
            {
                // Nothing further is available, and the directory removal below is
                // still worth attempting.
            }

            postmaster.Dispose();
        }

        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (IOException exception)
        {
            // Never silent: a directory we could not remove is disk we borrowed and
            // did not give back, and the customer has to be told where it is.
            await Console.Error.WriteLineAsync(
                $"proofdrill: could not remove the working directory '{_root}': {exception.Message}")
                .ConfigureAwait(false);
        }
    }
}
