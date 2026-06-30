using System.Net;

namespace ClaudeIPGuard.Core;

public sealed class DecisionEngine
{
    public GuardDecision Evaluate(
        GuardSettings settings,
        IpObservation ip,
        FirewallSnapshot firewall,
        ProcessSnapshot process,
        bool networkChanged)
    {
        if (networkChanged && settings.BlockImmediatelyOnNetworkChange)
        {
            return Block(settings, SafetyStatus.Unknown, process, "Network changed: Claude is blocked before verification.");
        }

        if (firewall.RuleStatus is FirewallRuleStatus.Unknown or FirewallRuleStatus.Error)
        {
            return Block(settings, SafetyStatus.Unknown, process, "Firewall status is unknown or errored.");
        }

        if (!ip.CheckSucceeded || ip.PublicIp is null)
        {
            return Block(settings, SafetyStatus.Unknown, process, ip.Error ?? "Public IP check failed.");
        }

        if (ip.ProviderMismatch && settings.BlockOnProviderMismatch)
        {
            return new GuardDecision(
                SafetyStatus.Danger,
                IsNetworkAllowed: false,
                ShouldBlockNetwork: true,
                ShouldKillClaude: false,
                FirewallCommand.KeepBlocked,
                string.IsNullOrWhiteSpace(ip.Error) ? "Different IP providers disagree." : ip.Error);
        }

        var modeDecision = settings.Mode switch
        {
            ProtectionMode.BlockCountries => EvaluateCountryMode(settings, ip, process),
            ProtectionMode.IpAllowlist => EvaluateAllowlistMode(settings, ip.PublicIp, process),
            _ => Block(settings, SafetyStatus.Unknown, process, "Unknown protection mode.")
        };

        if (modeDecision.Status != SafetyStatus.Safe)
        {
            return modeDecision;
        }

        return new GuardDecision(
            SafetyStatus.Safe,
            IsNetworkAllowed: true,
            ShouldBlockNetwork: false,
            ShouldKillClaude: false,
            FirewallCommand.AllowIfVerifiedSafe,
            "IP verified as safe.");
    }

    private static GuardDecision EvaluateCountryMode(GuardSettings settings, IpObservation ip, ProcessSnapshot process)
    {
        if (string.IsNullOrWhiteSpace(ip.CountryCode))
        {
            return Block(settings, SafetyStatus.Unknown, process, "Country check failed.");
        }

        var country = ip.CountryCode.Trim().ToUpperInvariant();
        var blocked = settings.BlockedCountries
            .Select(c => c.Trim().ToUpperInvariant())
            .Where(c => c.Length == 2)
            .Contains(country);

        if (blocked)
        {
            return Block(settings, SafetyStatus.Danger, process, $"Country {country} is blocked.");
        }

        return SafeCandidate();
    }

    private static GuardDecision EvaluateAllowlistMode(GuardSettings settings, IPAddress address, ProcessSnapshot process)
    {
        var ranges = settings.AllowedIpCidrs
            .Select(item => CidrRange.TryParse(item, out var range) ? range : null)
            .Where(range => range is not null)
            .Cast<CidrRange>()
            .ToList();

        if (ranges.Count == 0)
        {
            return Block(settings, SafetyStatus.Unknown, process, "IP allowlist is empty or invalid.");
        }

        if (!ranges.Any(range => range.Contains(address)))
        {
            return Block(settings, SafetyStatus.Danger, process, "Current public IP is not in the allowlist.");
        }

        return SafeCandidate();
    }

    private static GuardDecision SafeCandidate() =>
        new(SafetyStatus.Safe, true, false, false, FirewallCommand.AllowIfVerifiedSafe, "IP verified as safe.");

    private static GuardDecision Block(GuardSettings settings, SafetyStatus status, ProcessSnapshot process, string reason) =>
        new(
            status,
            IsNetworkAllowed: false,
            ShouldBlockNetwork: true,
            ShouldKillClaude: settings.StrictMode && status == SafetyStatus.Danger && process.IsClaudeRunning,
            FirewallCommand.KeepBlocked,
            reason);
}
