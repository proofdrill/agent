using System.Diagnostics;
using System.Text;

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
