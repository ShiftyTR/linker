namespace linker.tunnel.transport;

// Failure is scoped to a peer/node pair: an offline peer must not disable a node for everyone.
public sealed class RelayNodeBackoff
{
    private readonly object gate = new();
    private readonly Dictionary<(string Peer, string Node), (int Failures, long RetryAt)> failures = new();
    public long Remaining(string peer, string node)
    {
        lock (gate) return failures.TryGetValue((peer, node), out var value) ? Math.Max(0, value.RetryAt - Environment.TickCount64) : 0;
    }
    public void Failed(string peer, string node)
    {
        if (string.IsNullOrEmpty(node)) return;
        lock (gate)
        {
            if (failures.Count >= 256)
                foreach (var key in failures.OrderBy(x => x.Value.RetryAt).Take(64).Select(x => x.Key).ToArray()) failures.Remove(key);
            failures.TryGetValue((peer, node), out var previous);
            int count = Math.Min(previous.Failures + 1, 5);
            failures[(peer, node)] = (count, Environment.TickCount64 + Math.Min(30000, 1000 * (1 << count)));
        }
    }
    public void Succeeded(string peer, string node) { lock (gate) failures.Remove((peer, node)); }
}
