namespace ClaudeIPGuard.Core;

public static class NetworkChangeRetryPolicy
{
    public static IReadOnlyList<TimeSpan> VerificationDelays { get; } =
    [
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(10),
        TimeSpan.FromSeconds(20),
        TimeSpan.FromSeconds(35)
    ];
}
