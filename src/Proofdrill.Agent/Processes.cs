using System.Diagnostics;
using System.Text;
using Proofdrill.Agent.Protocol;
using Proofdrill.Agent.Storage;

namespace Proofdrill.Agent;

internal sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;

    /// <summary>A one line description for an error message that has to name the cause.</summary>
    public string Describe(string what) =>
        $"{what} exited {ExitCode}" +
        (StandardError.Length == 0 ? "" : $": {StandardError.Trim().ReplaceLineEndings(" ")}");
}

/// <summary>
/// Every external command goes through here. Arguments are passed as a list and
/// never as one string: this process builds command lines out of paths that
/// arrive from a customer's configuration, and a shell in the middle of that is
/// an injection surface we have no reason to own.
/// </summary>
internal static class Processes
{
    /// <summary>
    /// What no child of this agent has any use for: the registration token and
    /// the storage keys.
    /// <para>
    /// A child process inherits the environment, so without this the customer's
    /// read-only backup keys are sitting in the memory of a PostgreSQL server
    /// that is about to run SQL somebody else wrote. Nothing here needs them —
    /// the fetch is done by this process over HTTP before the cluster exists —
    /// and removing them means the boundary around a customer assertion does not
    /// rest on that SQL being unable to reach `COPY … FROM PROGRAM`. It cannot,
    /// and there is nothing there to read either way.
    /// </para>
    /// </summary>
    private static readonly string[] Secrets =
    [
        ReportEnvelope.TokenVariable,
        ArtefactLocator.AccessKeyVariable,
        ArtefactLocator.SecretKeyVariable,
    ];

    public static async Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? environment = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var info = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        if (environment is not null)
        {
            foreach (var (key, value) in environment)
            {
                info.Environment[key] = value;
            }
        }

        WithoutSecrets(info);

        using var process = new Process { StartInfo = info };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        process.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };

        if (!process.Start())
        {
            throw new InvalidOperationException($"could not start {fileName}");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout is { } window)
        {
            limit.CancelAfter(window);
        }

        try
        {
            await process.WaitForExitAsync(limit.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Killing the whole tree rather than the process: postgres forks, and
            // leaving orphaned backends running on somebody else's machine is
            // exactly the class of behaviour this agent must never have.
            TryKill(process);
            throw new TimeoutException(
                $"{Path.GetFileName(fileName)} did not finish within {timeout?.TotalSeconds ?? 0:0} s and was stopped");
        }

        return new ProcessResult(process.ExitCode, stdout.ToString(), stderr.ToString());
    }

    /// <summary>
    /// Strips <see cref="Secrets"/> from what a child process will inherit. Public
    /// to this assembly because the postmaster is started directly rather than
    /// through <see cref="RunAsync"/> — it is a long-lived process this agent
    /// watches, not a command it waits for — and it is the one child that must
    /// most certainly not carry them.
    /// </summary>
    public static void WithoutSecrets(ProcessStartInfo info)
    {
        foreach (var name in Secrets)
        {
            info.Environment.Remove(name);
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception)
        {
            // The process is already gone, or we cannot signal it. Either way there
            // is nothing further to do and hiding a failure here would be worse
            // than the original timeout.
        }
    }
}
