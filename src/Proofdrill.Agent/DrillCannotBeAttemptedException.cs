namespace Proofdrill.Agent;

/// <summary>
/// The drill could not be started, or could not be carried far enough to judge
/// the backup.
/// <para>
/// This is a **correction, not a verdict**, and the distinction is load bearing:
/// a misconfiguration, a key that is too narrow, a full disk or an incompatible
/// major version says nothing about whether the backup holds, and must move the
/// clock in neither direction. A single red FAILED covering both throws away the
/// conversation exactly where the product is most valuable — the first drill is
/// red more often than anybody expects, and the instinctive reading of that is
/// "your tool is broken". See <c>docs/03</c> §8.1 in the control plane.
/// </para>
/// </summary>
internal sealed class DrillCannotBeAttemptedException(string message) : Exception(message);
