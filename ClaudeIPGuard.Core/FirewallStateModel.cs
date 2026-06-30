namespace ClaudeIPGuard.Core;

public static class FirewallStateModel
{
    private const string OwnRulePrefix = "ClaudeIPGuard_Block_ClaudeDesktop";

    public static FirewallSnapshot ParseNetshShowRule(int exitCode, string output, string error, DateTimeOffset checkedAt)
    {
        var combined = $"{output}{Environment.NewLine}{error}";
        if (exitCode != 0 && IsRuleMissingOutput(combined))
        {
            return new FirewallSnapshot(FirewallRuleStatus.RuleInactive, FirewallAccessStatus.Allowed, "verify", null, checkedAt);
        }

        if (exitCode != 0)
        {
            return new FirewallSnapshot(FirewallRuleStatus.Error, FirewallAccessStatus.Unknown, "verify", string.IsNullOrWhiteSpace(error) ? output : error, checkedAt);
        }

        var exists = combined.Contains("ClaudeIPGuard_Block_ClaudeDesktop_Main", StringComparison.OrdinalIgnoreCase);
        if (!exists)
        {
            return new FirewallSnapshot(FirewallRuleStatus.RuleInactive, FirewallAccessStatus.Allowed, "verify", null, checkedAt);
        }

        var enabled = ContainsEnabledYes(combined);
        var disabled = ContainsEnabledNo(combined);

        if (!enabled && !disabled)
        {
            return new FirewallSnapshot(
                FirewallRuleStatus.RuleActive,
                FirewallAccessStatus.Blocked,
                "verify",
                "Claude firewall rule exists; enabled state could not be parsed, so it is treated as blocked.",
                checkedAt);
        }

        return new FirewallSnapshot(
            enabled ? FirewallRuleStatus.RuleActive : FirewallRuleStatus.RuleInactive,
            enabled ? FirewallAccessStatus.Blocked : FirewallAccessStatus.Allowed,
            "verify",
            null,
            checkedAt);
    }

    public static FirewallSnapshot ParseNetshShowAllOwnRules(int exitCode, string output, string error, DateTimeOffset checkedAt)
    {
        var combined = $"{output}{Environment.NewLine}{error}";
        if (exitCode != 0)
        {
            return new FirewallSnapshot(FirewallRuleStatus.Error, FirewallAccessStatus.Unknown, "verify", string.IsNullOrWhiteSpace(error) ? output : error, checkedAt);
        }

        var relevantBlocks = SplitRuleBlocks(combined)
            .Where(block => block.Contains(OwnRulePrefix, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (relevantBlocks.Count == 0)
        {
            return new FirewallSnapshot(FirewallRuleStatus.RuleInactive, FirewallAccessStatus.Allowed, "verify", null, checkedAt);
        }

        var anyActiveBlock = relevantBlocks.Any(ContainsEnabledYes);
        var allClearlyDisabled = relevantBlocks.All(ContainsEnabledNo);

        if (!anyActiveBlock && !allClearlyDisabled)
        {
            return new FirewallSnapshot(
                FirewallRuleStatus.RuleActive,
                FirewallAccessStatus.Blocked,
                "verify",
                "Claude firewall rule exists; enabled state could not be parsed, so it is treated as blocked.",
                checkedAt);
        }

        return new FirewallSnapshot(
            anyActiveBlock ? FirewallRuleStatus.RuleActive : FirewallRuleStatus.RuleInactive,
            anyActiveBlock ? FirewallAccessStatus.Blocked : FirewallAccessStatus.Allowed,
            "verify",
            null,
            checkedAt);
    }

    public static bool IsRuleMissingOutput(string output)
    {
        return output.Contains("No rules match", StringComparison.OrdinalIgnoreCase)
            || output.Contains("No rules match the specified criteria", StringComparison.OrdinalIgnoreCase)
            || output.Contains("Ни одно правило не соответствует", StringComparison.OrdinalIgnoreCase)
            || output.Contains("Нет правил", StringComparison.OrdinalIgnoreCase)
            || output.Contains("не соответствует указанным критериям", StringComparison.OrdinalIgnoreCase)
            || output.Contains("РќРё РѕРґРЅРѕ", StringComparison.OrdinalIgnoreCase)
            || output.Contains("РЅРµ СЃРѕРѕС‚РІРµС‚СЃС‚РІСѓРµС‚", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsAccessDeniedOutput(string output)
    {
        return output.Contains("Access is denied", StringComparison.OrdinalIgnoreCase)
            || output.Contains("Отказано в доступе", StringComparison.OrdinalIgnoreCase)
            || output.Contains("требуется повышение прав", StringComparison.OrdinalIgnoreCase)
            || output.Contains("РћС‚РєР°Р·Р°РЅРѕ", StringComparison.OrdinalIgnoreCase)
            || output.Contains("С‚СЂРµР±СѓРµС‚СЃСЏ", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsEnabledYes(string block)
    {
        return EnabledLines(block).Any(line =>
            line.Contains("Yes", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Да", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Р”Р°", StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsEnabledNo(string block)
    {
        return EnabledLines(block).Any(line =>
            line.Contains("No", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Нет", StringComparison.OrdinalIgnoreCase)
            || line.Contains("РќРµС‚", StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> EnabledLines(string block)
    {
        return block
            .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line =>
                line.Contains("Enabled", StringComparison.OrdinalIgnoreCase)
                || line.Contains("Включено", StringComparison.OrdinalIgnoreCase)
                || line.Contains("Р’РєР»СЋС‡РµРЅРѕ", StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> SplitRuleBlocks(string output)
    {
        return output
            .Split("Rule Name:", StringSplitOptions.RemoveEmptyEntries)
            .Select(block => $"Rule Name:{block}");
    }
}
