using System.Net;

namespace ClaudeIPGuard.Core;

public sealed class IpAddressComparer : IEqualityComparer<IPAddress>
{
    public bool Equals(IPAddress? x, IPAddress? y) => string.Equals(Normalize(x), Normalize(y), StringComparison.OrdinalIgnoreCase);
    public int GetHashCode(IPAddress obj) => Normalize(obj).GetHashCode(StringComparison.OrdinalIgnoreCase);

    private static string Normalize(IPAddress? address)
    {
        if (address is null)
        {
            return "";
        }

        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString();
    }
}
