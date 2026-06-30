using System.Net;
using System.Net.Sockets;

namespace ClaudeIPGuard.Core;

public sealed class CidrRange
{
    public IPAddress Network { get; }
    public int PrefixLength { get; }
    public AddressFamily AddressFamily => Network.AddressFamily;

    private readonly byte[] _networkBytes;
    private readonly byte[] _maskBytes;

    private CidrRange(IPAddress network, int prefixLength)
    {
        Network = network;
        PrefixLength = prefixLength;
        _networkBytes = NormalizeBytes(network);
        _maskBytes = BuildMask(_networkBytes.Length, prefixLength);
    }

    public static bool TryParse(string text, out CidrRange? range)
    {
        range = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        var parts = trimmed.Split('/', 2);
        if (!IPAddress.TryParse(parts[0], out var address))
        {
            return false;
        }

        var normalized = NormalizeAddress(address);
        var maxPrefix = normalized.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = maxPrefix;

        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > maxPrefix))
        {
            return false;
        }

        var bytes = NormalizeBytes(normalized);
        var mask = BuildMask(bytes.Length, prefix);
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(bytes[i] & mask[i]);
        }

        range = new CidrRange(new IPAddress(bytes), prefix);
        return true;
    }

    public bool Contains(IPAddress address)
    {
        var normalized = NormalizeAddress(address);
        if (normalized.AddressFamily != AddressFamily)
        {
            return false;
        }

        var bytes = NormalizeBytes(normalized);
        for (var i = 0; i < bytes.Length; i++)
        {
            if ((bytes[i] & _maskBytes[i]) != _networkBytes[i])
            {
                return false;
            }
        }

        return true;
    }

    public override string ToString() => $"{Network}/{PrefixLength}";

    private static IPAddress NormalizeAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        return address;
    }

    private static byte[] NormalizeBytes(IPAddress address) => NormalizeAddress(address).GetAddressBytes();

    private static byte[] BuildMask(int length, int prefixLength)
    {
        var mask = new byte[length];
        var bitsLeft = prefixLength;
        for (var i = 0; i < mask.Length; i++)
        {
            if (bitsLeft >= 8)
            {
                mask[i] = 0xff;
                bitsLeft -= 8;
            }
            else if (bitsLeft > 0)
            {
                mask[i] = (byte)(0xff << (8 - bitsLeft));
                bitsLeft = 0;
            }
        }

        return mask;
    }
}
