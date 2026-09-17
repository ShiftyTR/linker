using linker.libs;
using linker.tunnel.connection;
using System.Collections.Concurrent;

namespace linker.messenger.channel;

public sealed class ChannelConnectionCaching
{
    private readonly object gate = new();
    private readonly Dictionary<(string Transaction, string Peer), (ITunnelConnection Owner, ITunnelConnection Standby)> fallbacks = new();
    public VersionManager Version { get; } = new();
    public ConcurrentDictionary<string, ConcurrentDictionary<string, ITunnelConnection>> Connections { get; } = new();
    public ConcurrentDictionary<string, ITunnelConnection> this[string transactionId] => Connections.GetOrAdd(transactionId, _ => new());
    private static (string, string) Key(ITunnelConnection c) => (c.TransactionId, c.RemoteMachineId);

    public bool TryGetValue(string machineId, string transactionId, out ITunnelConnection connection) =>
        this[transactionId].TryGetValue(machineId, out connection);

    public ITunnelConnection Add(ITunnelConnection connection)
    {
        lock (gate) { this[connection.TransactionId][connection.RemoteMachineId] = connection; Version.Increment(); }
        return connection;
    }

    // Promotion and standby ownership change atomically. A stale close cannot restore over a newer path.
    public bool TryReplace(ITunnelConnection expected, ITunnelConnection replacement)
    {
        ITunnelConnection obsolete = null;
        lock (gate)
        {
            var entries = this[replacement.TransactionId];
            entries.TryGetValue(replacement.RemoteMachineId, out var current);
            if (!ReferenceEquals(current, expected)) return false;
            entries[replacement.RemoteMachineId] = replacement;
            if (fallbacks.Remove(Key(replacement), out var previous)) obsolete = previous.Standby;
            if (expected?.Connected == true) fallbacks[Key(replacement)] = (replacement, expected);
            Version.Increment();
        }
        if (obsolete != null && !ReferenceEquals(obsolete, expected) && !ReferenceEquals(obsolete, replacement)) obsolete.Dispose();
        return true;
    }

    public void SetFallback(ITunnelConnection owner, ITunnelConnection standby)
    {
        ITunnelConnection obsolete = null;
        bool accepted;
        lock (gate)
        {
            accepted = TryGetValue(owner.RemoteMachineId, owner.TransactionId, out var current) && ReferenceEquals(current, owner);
            if (accepted)
            {
                if (fallbacks.Remove(Key(owner), out var previous)) obsolete = previous.Standby;
                fallbacks[Key(owner)] = (owner, standby);
            }
        }
        if (!accepted) standby.Dispose();
        if (obsolete != null && !ReferenceEquals(obsolete, standby) && !ReferenceEquals(obsolete, owner)) obsolete.Dispose();
    }

    public ITunnelConnection Remove(ITunnelConnection connection)
    {
        if (connection == null) return null;
        lock (gate)
        {
            var entries = this[connection.TransactionId];
            if (!entries.TryGetValue(connection.RemoteMachineId, out var current) || !ReferenceEquals(current, connection))
            {
                if (fallbacks.TryGetValue(Key(connection), out var old) && ReferenceEquals(old.Standby, connection)) fallbacks.Remove(Key(connection));
                return null;
            }
            entries.TryRemove(new KeyValuePair<string, ITunnelConnection>(connection.RemoteMachineId, connection));
            Version.Increment();
            if (fallbacks.Remove(Key(connection), out var fallback) && ReferenceEquals(fallback.Owner, connection) && fallback.Standby.Connected)
            {
                entries[connection.RemoteMachineId] = fallback.Standby;
                return fallback.Standby;
            }
            return null;
        }
    }

    public void Remove(string machineId, string transactionId)
    {
        ITunnelConnection active;
        ITunnelConnection standby = null;
        lock (gate)
        {
            this[transactionId].TryRemove(machineId, out active);
            if (fallbacks.Remove((transactionId, machineId), out var fallback)) standby = fallback.Standby;
            Version.Increment();
        }
        active?.Dispose();
        standby?.Dispose();
    }

    public void Clear()
    {
        ITunnelConnection[] all;
        lock (gate)
        {
            all = Connections.Values.SelectMany(x => x.Values).Concat(fallbacks.Values.Select(x => x.Standby)).Distinct().ToArray();
            foreach (var entries in Connections.Values) entries.Clear();
            fallbacks.Clear();
            Version.Increment();
        }
        foreach (var connection in all) connection.Dispose();
    }
}
