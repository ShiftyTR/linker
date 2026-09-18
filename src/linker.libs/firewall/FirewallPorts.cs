using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace linker.libs.firewall;

// Source-linked by the web tier so saved and enforced port expressions agree.
public static class FirewallPorts
{
    public readonly record struct Range(ushort Start, ushort End)
    {
        public bool Contains(ushort port) => port >= Start && port <= End;
    }
    public static bool TryParse(string expression, out Range[] ranges, out string normalized)
    {
        expression = expression?.Trim() ?? "";
        ranges = Array.Empty<Range>(); normalized = "";
        if (expression is "" or "0" or "*")
        {
            ranges = new[] { new Range(0, ushort.MaxValue) }; normalized = "0"; return true;
        }
        if (expression.Length > 300) return false;
        var parsed = new List<Range>();
        foreach (var token in expression.Split(','))
        {
            var parts = token.Trim().Split('-');
            if (parts.Length is < 1 or > 2 || !Port(parts[0], out var start)) return false;
            var end = start;
            if (parts.Length == 2 && (!Port(parts[1], out end) || end < start)) return false;
            parsed.Add(new Range(start, end));
        }
        ranges = parsed.Distinct().OrderBy(r => r.Start).ThenBy(r => r.End).ToArray();
        normalized = string.Join(",", ranges.Select(r => r.Start == r.End ? r.Start.ToString(CultureInfo.InvariantCulture) : $"{r.Start}-{r.End}"));
        return ranges.Length > 0;
    }
    private static bool Port(string value, out ushort port) =>
        ushort.TryParse(value.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port > 0;
}
