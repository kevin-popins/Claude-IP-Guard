using ClaudeIPGuard.Core;
using System.Net;

var tests = new List<(string Name, Action Test)>
{
    ("CIDR IPv4 contains address", TestCidrIpv4),
    ("CIDR IPv6 contains address", TestCidrIpv6),
    ("Country block produces danger", TestCountryBlock),
    ("Allowlist permits matching CIDR", TestAllowlistSafe),
    ("Unknown IP fails closed", TestUnknownIpBlocks),
    ("Provider mismatch fails closed", TestProviderMismatchBlocks),
    ("Provider mismatch blocks without automatic kill", TestProviderMismatchDoesNotKill),
    ("Diagnostic split route is ignored for selected IP", TestDiagnosticSplitRouteIgnored),
    ("Single authoritative route outlier is ignored by majority", TestSingleAuthoritativeOutlierIgnored),
    ("Load balanced VPN egress pool is accepted", TestLoadBalancedVpnEgressPoolAccepted),
    ("Different egress pools are rejected", TestDifferentEgressPoolsRejected),
    ("Authoritative provider mismatch is detected", TestAuthoritativeMismatchDetected),
    ("Firewall unknown fails closed", TestFirewallUnknownBlocks),
    ("Firewall missing rule is inactive allowed", TestFirewallMissingRuleInactive),
    ("Firewall active rule is blocked", TestFirewallActiveRuleBlocked),
    ("Firewall single unparsable rule fails closed", TestFirewallSingleUnparsableRuleFailsClosed),
    ("Firewall duplicate own rules are blocked", TestFirewallDuplicateOwnRulesBlocked),
    ("Firewall localized active own rule is blocked", TestFirewallLocalizedOwnRuleBlocked),
    ("Firewall unparsable own rule fails closed", TestFirewallUnparsableOwnRuleFailsClosed),
    ("Firewall missing Russian mojibake recognized", TestFirewallMissingMojibakeRecognized),
    ("Network change blocks before verification", TestNetworkChangeBlocksFirst),
    ("Network change unknown does not kill before IP result", TestNetworkChangeUnknownDoesNotKill),
    ("Network change retry delays are staged", TestNetworkChangeRetryDelays),
    ("Strict mode controls automatic kill", TestStrictModeKill),
    ("Claude helper service is related but not desktop running", TestClaudeHelperServiceIsNotDesktopRunning),
    ("Process classifier detects Claude children", TestProcessClassifier)
};

var failed = 0;
foreach (var (name, test) in tests)
{
    try
    {
        test();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.WriteLine($"FAIL {name}: {ex.Message}");
    }
}

Console.WriteLine();
Console.WriteLine($"{tests.Count - failed}/{tests.Count} tests passed.");
return failed == 0 ? 0 : 1;

static void TestCidrIpv4()
{
    Assert(CidrRange.TryParse("185.123.45.0/24", out var range), "range should parse");
    Assert(range!.Contains(IPAddress.Parse("185.123.45.200")), "address should be in range");
    Assert(!range.Contains(IPAddress.Parse("185.123.46.1")), "address should be outside range");
}

static void TestCidrIpv6()
{
    Assert(CidrRange.TryParse("2a06:98c0::/29", out var range), "range should parse");
    Assert(range!.Contains(IPAddress.Parse("2a06:98c0::1")), "address should be in range");
    Assert(!range.Contains(IPAddress.Parse("2a07:98c0::1")), "address should be outside range");
}

static void TestCountryBlock()
{
    var decision = Engine().Evaluate(
        new GuardSettings { Mode = ProtectionMode.BlockCountries, BlockedCountries = ["RU"], StrictMode = true },
        Ip("188.1.2.3", country: "RU"),
        Firewall(FirewallRuleStatus.RuleActive),
        Process(running: true),
        networkChanged: false);
    Assert(decision.Status == SafetyStatus.Danger, "blocked country should be danger");
    Assert(decision.ShouldBlockNetwork, "network should be blocked");
    Assert(decision.ShouldKillClaude, "strict mode should kill running Claude");
}

static void TestAllowlistSafe()
{
    var decision = Engine().Evaluate(
        new GuardSettings { Mode = ProtectionMode.IpAllowlist, AllowedIpCidrs = ["104.28.10.0/24"] },
        Ip("104.28.10.15", country: "US"),
        Firewall(FirewallRuleStatus.RuleActive),
        Process(running: false),
        networkChanged: false);
    Assert(decision.Status == SafetyStatus.Safe, "matching allowlist should be safe");
    Assert(decision.FirewallCommand == FirewallCommand.AllowIfVerifiedSafe, "safe state may unblock only after verification");
}

static void TestUnknownIpBlocks()
{
    var decision = Engine().Evaluate(
        new GuardSettings(),
        IpObservation.Unknown("provider failed"),
        Firewall(FirewallRuleStatus.RuleActive),
        Process(running: false),
        networkChanged: false);
    Assert(decision.Status == SafetyStatus.Unknown, "unknown IP should be unknown");
    Assert(decision.ShouldBlockNetwork, "unknown IP should block");
}

static void TestProviderMismatchBlocks()
{
    var observation = Ip("104.28.10.15", country: "US") with { ProviderMismatch = true };
    var decision = Engine().Evaluate(
        new GuardSettings { BlockOnProviderMismatch = true },
        observation,
        Firewall(FirewallRuleStatus.RuleActive),
        Process(running: false),
        networkChanged: false);
    Assert(decision.Status == SafetyStatus.Danger, "provider mismatch should be danger");
    Assert(decision.ShouldBlockNetwork, "provider mismatch should block network");
}

static void TestProviderMismatchDoesNotKill()
{
    var observation = Ip("104.28.10.15", country: "US") with { ProviderMismatch = true, Error = "Authoritative IP providers disagree." };
    var decision = Engine().Evaluate(
        new GuardSettings { BlockOnProviderMismatch = true, StrictMode = true },
        observation,
        Firewall(FirewallRuleStatus.RuleActive),
        Process(running: true),
        networkChanged: false);
    Assert(decision.ShouldBlockNetwork, "provider mismatch should block network");
    Assert(!decision.ShouldKillClaude, "provider mismatch should not kill before a blocked country is confirmed");
}

static void TestDiagnosticSplitRouteIgnored()
{
    var selected = IpDecisionModel.SelectAuthoritativeAddress(
    [
        new IpProviderReading("api.ipify.org", IPAddress.Parse("5.34.179.158"), null),
        new IpProviderReading("cloudflare trace", IPAddress.Parse("5.34.179.158"), null),
        new IpProviderReading("ifconfig.me", IPAddress.Parse("188.232.64.170"), null, IsAuthoritative: false)
    ]);
    Assert(selected.Address?.ToString() == "5.34.179.158", "authoritative providers should choose VPN IP");
    Assert(!selected.Mismatch, "diagnostic provider should not cause authoritative mismatch");
}

static void TestSingleAuthoritativeOutlierIgnored()
{
    var selected = IpDecisionModel.SelectAuthoritativeAddress(
    [
        new IpProviderReading("api.ipify.org", IPAddress.Parse("188.232.64.170"), null),
        new IpProviderReading("api.ip.sb", IPAddress.Parse("5.34.179.158"), null),
        new IpProviderReading("ipinfo.io", IPAddress.Parse("5.34.179.158"), null),
        new IpProviderReading("cloudflare trace", IPAddress.Parse("5.34.179.158"), null)
    ]);
    Assert(selected.Address?.ToString() == "5.34.179.158", "majority should choose the VPN IP");
    Assert(!selected.Mismatch, "single route outlier should not cause mismatch");
}

static void TestLoadBalancedVpnEgressPoolAccepted()
{
    var selected = IpDecisionModel.SelectAuthoritativeAddress(
    [
        new IpProviderReading("api.ipify.org", IPAddress.Parse("64.188.66.182"), null),
        new IpProviderReading("api.ip.sb", IPAddress.Parse("64.188.67.83"), null),
        new IpProviderReading("ipinfo.io", IPAddress.Parse("64.188.67.145"), null),
        new IpProviderReading("cloudflare trace", IPAddress.Parse("64.188.66.182"), null)
    ]);
    Assert(selected.Address is not null, "egress pool should choose a representative IP");
    Assert(!selected.Mismatch, "same /23 VPN egress pool should not cause mismatch");
}

static void TestDifferentEgressPoolsRejected()
{
    var selected = IpDecisionModel.SelectAuthoritativeAddress(
    [
        new IpProviderReading("api.ipify.org", IPAddress.Parse("64.188.66.182"), null),
        new IpProviderReading("api.ip.sb", IPAddress.Parse("64.188.68.83"), null),
        new IpProviderReading("ipinfo.io", IPAddress.Parse("185.199.108.1"), null)
    ]);
    Assert(selected.Mismatch, "different egress pools without majority should be mismatch");
}

static void TestAuthoritativeMismatchDetected()
{
    var selected = IpDecisionModel.SelectAuthoritativeAddress(
    [
        new IpProviderReading("api.ipify.org", IPAddress.Parse("5.34.179.158"), null),
        new IpProviderReading("cloudflare trace", IPAddress.Parse("188.232.64.170"), null),
        new IpProviderReading("ifconfig.me", IPAddress.Parse("188.232.64.170"), null, IsAuthoritative: false)
    ]);
    Assert(selected.Mismatch, "different authoritative providers should be mismatch");
}

static void TestFirewallUnknownBlocks()
{
    var decision = Engine().Evaluate(
        new GuardSettings(),
        Ip("104.28.10.15", country: "US"),
        Firewall(FirewallRuleStatus.Unknown),
        Process(running: false),
        networkChanged: false);
    Assert(decision.ShouldBlockNetwork, "unknown firewall should block");
}

static void TestFirewallMissingRuleInactive()
{
    var state = FirewallStateModel.ParseNetshShowRule(1, "No rules match the specified criteria.", "", DateTimeOffset.Now);
    Assert(state.RuleStatus == FirewallRuleStatus.RuleInactive, "missing rule should be inactive");
    Assert(state.AccessStatus == FirewallAccessStatus.Allowed, "missing rule should mean allowed network access");
}

static void TestFirewallActiveRuleBlocked()
{
    var output = """
Rule Name:                            ClaudeIPGuard_Block_ClaudeDesktop_Main
Enabled:                              Yes
Direction:                            Out
Action:                               Block
""";
    var state = FirewallStateModel.ParseNetshShowRule(0, output, "", DateTimeOffset.Now);
    Assert(state.RuleStatus == FirewallRuleStatus.RuleActive, "enabled rule should be active");
    Assert(state.AccessStatus == FirewallAccessStatus.Blocked, "enabled block rule should mean blocked");
}

static void TestFirewallSingleUnparsableRuleFailsClosed()
{
    var output = """
Rule Name:                            ClaudeIPGuard_Block_ClaudeDesktop_Main
----------------------------------------------------------------------
Direction:                            Out
Action:                               Block
""";
    var state = FirewallStateModel.ParseNetshShowRule(0, output, "", DateTimeOffset.Now);
    Assert(state.RuleStatus == FirewallRuleStatus.RuleActive, "own rule with no enabled field should fail closed as active");
    Assert(state.AccessStatus == FirewallAccessStatus.Blocked, "own rule with no enabled field should not be allowed");
}

static void TestFirewallDuplicateOwnRulesBlocked()
{
    var output = """
Rule Name:                            ClaudeIPGuard_Block_ClaudeDesktop_Main
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Action:                               Block

Rule Name:                            ClaudeIPGuard_Block_ClaudeDesktop_Helper_1
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Action:                               Block
""";
    var state = FirewallStateModel.ParseNetshShowAllOwnRules(0, output, "", DateTimeOffset.Now);
    Assert(state.RuleStatus == FirewallRuleStatus.RuleActive, "any duplicate active block rule should be active");
    Assert(state.AccessStatus == FirewallAccessStatus.Blocked, "any duplicate active block rule should block");
}

static void TestFirewallLocalizedOwnRuleBlocked()
{
    var output = """
Имя правила:                          ClaudeIPGuard_Block_ClaudeDesktop_Main
----------------------------------------------------------------------
Включено:                             Да
Направление:                          Исходящие
Действие:                             Блокировать
""";
    var state = FirewallStateModel.ParseNetshShowAllOwnRules(0, output, "", DateTimeOffset.Now);
    Assert(state.RuleStatus == FirewallRuleStatus.RuleActive, "localized enabled own rule should be active");
    Assert(state.AccessStatus == FirewallAccessStatus.Blocked, "localized enabled own rule should block");
}

static void TestFirewallUnparsableOwnRuleFailsClosed()
{
    var output = """
Rule Name:                            ClaudeIPGuard_Block_ClaudeDesktop_Main
----------------------------------------------------------------------
Direction:                            Out
Action:                               Block
""";
    var state = FirewallStateModel.ParseNetshShowAllOwnRules(0, output, "", DateTimeOffset.Now);
    Assert(state.RuleStatus == FirewallRuleStatus.RuleActive, "own rule with unknown enabled state should fail closed as active");
    Assert(state.AccessStatus == FirewallAccessStatus.Blocked, "unknown own rule state should not be allowed");
}

static void TestFirewallMissingMojibakeRecognized()
{
    Assert(FirewallStateModel.IsRuleMissingOutput("РќРё РѕРґРЅРѕ РїСЂР°РІРёР»Рѕ РЅРµ СЃРѕРѕС‚РІРµС‚СЃС‚РІСѓРµС‚ СѓРєР°Р·Р°РЅРЅС‹Рј РєСЂРёС‚РµСЂРёСЏРј."), "Russian mojibake missing-rule output should be recognized");
}

static void TestNetworkChangeBlocksFirst()
{
    var decision = Engine().Evaluate(
        new GuardSettings { BlockImmediatelyOnNetworkChange = true },
        Ip("104.28.10.15", country: "US"),
        Firewall(FirewallRuleStatus.RuleActive),
        Process(running: false),
        networkChanged: true);
    Assert(decision.Status == SafetyStatus.Unknown, "network change should block before trusting IP");
}

static void TestNetworkChangeUnknownDoesNotKill()
{
    var decision = Engine().Evaluate(
        new GuardSettings { BlockImmediatelyOnNetworkChange = true, StrictMode = true },
        Ip("104.28.10.15", country: "US"),
        Firewall(FirewallRuleStatus.RuleActive),
        Process(running: true),
        networkChanged: true);
    Assert(decision.ShouldBlockNetwork, "network change should block network");
    Assert(!decision.ShouldKillClaude, "network change should not kill Claude before an unsafe IP is verified");
}

static void TestNetworkChangeRetryDelays()
{
    var delays = NetworkChangeRetryPolicy.VerificationDelays;
    Assert(delays.Count >= 3, "network change should have several settled checks");
    Assert(delays[0] >= TimeSpan.FromSeconds(1), "first settled check should wait for route changes");
    Assert(delays.SequenceEqual(delays.OrderBy(delay => delay)), "network change retry delays should be ordered");
}

static void TestStrictModeKill()
{
    var strictOff = Engine().Evaluate(
        new GuardSettings { StrictMode = false, BlockedCountries = ["RU"] },
        Ip("188.1.2.3", country: "RU"),
        Firewall(FirewallRuleStatus.RuleActive),
        Process(running: true),
        networkChanged: false);
    Assert(!strictOff.ShouldKillClaude, "strict mode disabled should not auto-kill");
}

static void TestClaudeHelperServiceIsNotDesktopRunning()
{
    var helperPath = @"C:\Program Files\WindowsApps\Claude_1.15962.1.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe";
    var snapshot = new ProcessSnapshot(
    [
        new ProcessInfo(10, 1, "cowork-svc", helperPath, null, IsClaudeRelated: true)
    ], DateTimeOffset.Now);
    Assert(snapshot.IsClaudeRunning, "Claude helper service should remain Claude-related");
    Assert(!snapshot.IsClaudeUserAppRunning, "helper service alone should not make Claude Desktop status running");
    Assert(snapshot.ClaudeHelperProcessCount == 1, "helper process should be counted separately");
}

static void TestProcessClassifier()
{
    var configured = new[] { @"C:\Users\me\AppData\Local\Programs\Claude\Claude.exe" };
    Assert(ProcessClassifier.IsClaudeRelated("Claude", null, null, configured, [], null), "name should match");
    Assert(ProcessClassifier.IsClaudeRelated("Claude Helper", null, null, configured, [], null), "Claude helper name should match");
    Assert(ProcessClassifier.IsClaudeRelated("Update", @"C:\Users\me\AppData\Local\Programs\Claude\Update.exe", null, configured, [], null), "path marker should match");
    Assert(ProcessClassifier.IsClaudeRelated("Electron Helper", null, null, configured, [42], 42), "child should match");
    Assert(!ProcessClassifier.IsClaudeRelated("Update", @"C:\Windows\System32\Update.exe", null, configured, [], null), "global update should not match");
    Assert(!ProcessClassifier.IsClaudeRelated("ClaudeIPGuard.App", @"C:\Users\me\AppData\Local\Programs\ClaudeIPGuard\ClaudeIPGuard.App.exe", null, configured, [], null), "guard process should not match itself");
    Assert(ProcessClassifier.IsClaudeRelated("claude", @"C:\Users\me\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe", null, configured, [], null), "Claude Code CLI should match");
}

static DecisionEngine Engine() => new();

static IpObservation Ip(string address, string country) =>
    new(IPAddress.Parse(address), country, "Test Country", "AS64500", "Example ISP", [new IpProviderReading("a", IPAddress.Parse(address), null), new IpProviderReading("b", IPAddress.Parse(address), null)], DateTimeOffset.Now, true, false, null);

static FirewallSnapshot Firewall(FirewallRuleStatus status) =>
    new(status, status == FirewallRuleStatus.RuleActive ? FirewallAccessStatus.Blocked : FirewallAccessStatus.Unknown, "test", null, DateTimeOffset.Now);

static ProcessSnapshot Process(bool running)
{
    var processes = running
        ? new[] { new ProcessInfo(42, null, "Claude", @"C:\Claude\Claude.exe", null, true) }
        : [];
    return new ProcessSnapshot(processes, DateTimeOffset.Now);
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
