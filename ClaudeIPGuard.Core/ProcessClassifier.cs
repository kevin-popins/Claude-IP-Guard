namespace ClaudeIPGuard.Core;

public static class ProcessClassifier
{
    private static readonly string[] ClaudeNames =
    [
        "claude",
        "anthropic claude"
    ];

    private static readonly string[] ClaudePathMarkers =
    [
        "\\claude\\",
        "\\anthropicclaude\\",
        "\\anthropic claude\\"
    ];

    public static bool IsClaudeRelated(
        string? processName,
        string? executablePath,
        string? commandLine,
        IEnumerable<string> configuredExecutablePaths,
        IEnumerable<int> knownClaudeProcessIds,
        int? parentProcessId)
    {
        var knownParents = knownClaudeProcessIds.ToHashSet();
        if (parentProcessId.HasValue && knownParents.Contains(parentProcessId.Value))
        {
            return true;
        }

        var configured = configuredExecutablePaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(Normalize)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var path = Normalize(executablePath ?? "");
        var command = commandLine ?? "";
        var name = (processName ?? "").Trim().ToLowerInvariant();

        if (!string.IsNullOrWhiteSpace(executablePath) && configured.Contains(Normalize(executablePath)))
        {
            return true;
        }

        if (ClaudeNames.Any(item =>
            name.Equals(item, StringComparison.OrdinalIgnoreCase)
            || name.StartsWith(item + " ", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (ClaudePathMarkers.Any(marker => path.Contains(marker, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return configured.Any(item => command.Contains(item, StringComparison.OrdinalIgnoreCase))
            || command.Contains("anthropic", StringComparison.OrdinalIgnoreCase)
            && command.Contains("claude", StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string path) =>
        path.Trim().Replace('/', '\\');
}
