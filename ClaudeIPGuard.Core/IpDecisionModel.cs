using System.Net;

namespace ClaudeIPGuard.Core;

public static class IpDecisionModel
{
    public static (IPAddress? Address, bool Mismatch, string? Error) SelectAuthoritativeAddress(IEnumerable<IpProviderReading> readings)
    {
        var authoritativeReadings = readings.Where(reading => reading.IsAuthoritative).ToList();
        var successfulReadings = authoritativeReadings
            .Where(reading => reading.Address is not null)
            .ToList();
        var groups = successfulReadings
            .GroupBy(reading => reading.Address!, new IpAddressComparer())
            .Select(group => new { Address = group.Key, Count = group.Count() })
            .OrderByDescending(group => group.Count)
            .ToList();

        if (groups.Count == 0)
        {
            return (null, false, "No authoritative IP provider returned a usable public IP.");
        }

        if (successfulReadings.Count < 2)
        {
            return (groups[0].Address, false, "Fewer than two authoritative IP providers agreed.");
        }

        var best = groups[0];
        var second = groups.Count > 1 ? groups[1] : null;
        var hasStrictMajority = best.Count > successfulReadings.Count / 2;
        var tiedWithAnotherRoute = second is not null && second.Count == best.Count;

        if (groups.Count > 1 && (!hasStrictMajority || tiedWithAnotherRoute))
        {
            if (IsSingleEgressPool(successfulReadings.Select(reading => reading.Address!)))
            {
                return (best.Address, false, null);
            }

            return (best.Address, true, "Authoritative IP providers disagree without a clear majority.");
        }

        return (best.Address, false, null);
    }

    public static bool IsSameEgressPool(IPAddress left, IPAddress right)
    {
        if (left.IsIPv4MappedToIPv6)
        {
            left = left.MapToIPv4();
        }

        if (right.IsIPv4MappedToIPv6)
        {
            right = right.MapToIPv4();
        }

        if (left.AddressFamily != right.AddressFamily)
        {
            return false;
        }

        var leftBytes = left.GetAddressBytes();
        var rightBytes = right.GetAddressBytes();
        if (leftBytes.Length != rightBytes.Length)
        {
            return false;
        }

        return leftBytes.Length switch
        {
            4 => leftBytes[0] == rightBytes[0]
                && leftBytes[1] == rightBytes[1]
                && (leftBytes[2] & 0xFE) == (rightBytes[2] & 0xFE),
            16 => leftBytes.Take(6).SequenceEqual(rightBytes.Take(6)),
            _ => false
        };
    }

    private static bool IsSingleEgressPool(IEnumerable<IPAddress> addresses)
    {
        var distinct = addresses.Distinct(new IpAddressComparer()).ToList();
        if (distinct.Count < 2)
        {
            return false;
        }

        var first = distinct[0];
        return distinct.All(address => IsSameEgressPool(first, address));
    }
}
