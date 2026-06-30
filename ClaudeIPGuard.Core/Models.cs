using System.Net;

namespace ClaudeIPGuard.Core;

public enum ProtectionMode
{
    BlockCountries,
    IpAllowlist
}

public enum SafetyStatus
{
    Safe,
    Blocked,
    Danger,
    Checking,
    Unknown
}

public enum FirewallRuleStatus
{
    Unknown,
    RuleActive,
    RuleInactive,
    Error
}

public enum FirewallAccessStatus
{
    Unknown,
    Allowed,
    Blocked
}

public enum MonitoringStatus
{
    Active,
    Paused,
    Error
}

public enum FirewallCommand
{
    KeepBlocked,
    AllowIfVerifiedSafe
}

public sealed class GuardSettings
{
    public ProtectionMode Mode { get; set; } = ProtectionMode.BlockCountries;
    public List<string> BlockedCountries { get; set; } = ["RU", "BY", "IR", "KP"];
    public List<string> AllowedIpCidrs { get; set; } = [];
    public List<string> ClaudeInstallDirectories { get; set; } = [];
    public List<string> ClaudeExecutablePaths { get; set; } = [];
    public bool StrictMode { get; set; } = true;
    public bool BlockOnUnknownIp { get; set; } = true;
    public bool BlockOnProviderMismatch { get; set; } = true;
    public bool BlockImmediatelyOnNetworkChange { get; set; } = true;
    public bool StartWithWindows { get; set; }
    public bool StartMinimizedToTray { get; set; }
    public bool ShowWindowsNotifications { get; set; } = true;
    public bool BringAppToFrontOnDanger { get; set; } = true;
    public int IpCheckIntervalSeconds { get; set; } = 5;
    public int UiRefreshIntervalSeconds { get; set; } = 1;
    public int ProcessMonitorIntervalSeconds { get; set; } = 1;
    public bool NetworkChangeEventsEnabled { get; set; } = true;
}

public sealed record IpProviderReading(string Provider, IPAddress? Address, string? Error, bool IsAuthoritative = true);

public sealed record IpObservation(
    IPAddress? PublicIp,
    string? CountryCode,
    string? CountryName,
    string? Asn,
    string? Provider,
    IReadOnlyList<IpProviderReading> ProviderReadings,
    DateTimeOffset? LastSuccessfulCheck,
    bool CheckSucceeded,
    bool ProviderMismatch,
    string? Error)
{
    public static IpObservation Unknown(string reason) =>
        new(null, null, null, null, null, [], null, false, false, reason);
}

public sealed record ProcessInfo(
    int ProcessId,
    int? ParentProcessId,
    string Name,
    string? ExecutablePath,
    string? CommandLine,
    bool IsClaudeRelated);

public sealed record ProcessSnapshot(
    IReadOnlyList<ProcessInfo> Processes,
    DateTimeOffset CheckedAt)
{
    public bool IsClaudeRunning => Processes.Any(p => p.IsClaudeRelated);
    public int ClaudeProcessCount => Processes.Count(p => p.IsClaudeRelated);
    public bool IsClaudeUserAppRunning => Processes.Any(IsClaudeUserAppProcess);
    public int ClaudeUserAppProcessCount => Processes.Count(IsClaudeUserAppProcess);
    public int ClaudeHelperProcessCount => Processes.Count(p => p.IsClaudeRelated && !IsClaudeUserAppProcess(p));
    public string ClaudeExecutablePath => Processes.FirstOrDefault(p => p.IsClaudeRelated)?.ExecutablePath ?? "";

    private static bool IsClaudeUserAppProcess(ProcessInfo process)
    {
        if (!process.IsClaudeRelated)
        {
            return false;
        }

        var name = process.Name.Trim();
        if (string.Equals(name, "claude", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "claude.exe", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var file = string.IsNullOrWhiteSpace(process.ExecutablePath)
            ? ""
            : Path.GetFileName(process.ExecutablePath);
        return string.Equals(file, "claude.exe", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed record FirewallSnapshot(
    FirewallRuleStatus RuleStatus,
    FirewallAccessStatus AccessStatus,
    string LastOperation,
    string? LastError,
    DateTimeOffset CheckedAt);

public sealed record GuardDecision(
    SafetyStatus Status,
    bool IsNetworkAllowed,
    bool ShouldBlockNetwork,
    bool ShouldKillClaude,
    FirewallCommand FirewallCommand,
    string Reason);

public sealed record GuardRuntimeState(
    IpObservation Ip,
    ProcessSnapshot Process,
    FirewallSnapshot Firewall,
    GuardDecision Decision,
    MonitoringStatus MonitoringStatus,
    DateTimeOffset? LastNetworkChange,
    DateTimeOffset UpdatedAt);
