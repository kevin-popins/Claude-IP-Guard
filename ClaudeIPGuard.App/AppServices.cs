using ClaudeIPGuard.Core;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Forms = System.Windows.Forms;

namespace ClaudeIPGuard.App;

public static class AppPaths
{
    public static string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ClaudeIPGuard");
    public static string Logs { get; } = Path.Combine(Root, "logs");
    public static string Diagnostics { get; } = Path.Combine(Root, "diagnostics");
    public static string SettingsFile { get; } = Path.Combine(Root, "settings.json");

    public static void Ensure()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(Diagnostics);
    }
}

public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public GuardSettings Load()
    {
        AppPaths.Ensure();
        if (!File.Exists(AppPaths.SettingsFile))
        {
            var settings = new GuardSettings();
            settings.MergeClaudeDetection(ClaudeInstallationDetector.Detect());
            Save(settings);
            return settings;
        }

        try
        {
            var json = File.ReadAllText(AppPaths.SettingsFile);
            var settings = JsonSerializer.Deserialize<GuardSettings>(json, JsonOptions) ?? new GuardSettings();
            settings.MergeClaudeDetection(ClaudeInstallationDetector.Detect());
            Save(settings);

            return settings;
        }
        catch
        {
            var settings = new GuardSettings();
            settings.MergeClaudeDetection(ClaudeInstallationDetector.Detect());
            return settings;
        }
    }

    public void Save(GuardSettings settings)
    {
        AppPaths.Ensure();
        File.WriteAllText(AppPaths.SettingsFile, JsonSerializer.Serialize(settings, JsonOptions));
        ConfigureAutostart(settings.StartWithWindows);
    }

    private static void ConfigureAutostart(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
            if (key is null)
            {
                return;
            }

            var exe = Environment.ProcessPath;
            if (enabled && !string.IsNullOrWhiteSpace(exe))
            {
                key.SetValue("ClaudeIPGuard", $"\"{exe}\" --minimized");
            }
            else
            {
                key.DeleteValue("ClaudeIPGuard", throwOnMissingValue: false);
            }
        }
        catch
        {
            // Autostart failure is shown through logs/status; it must not crash the guard.
        }
    }
}

public sealed record ClaudeDetectionResult(IReadOnlyList<string> InstallDirectories, IReadOnlyList<string> ExecutablePaths);

public static class GuardSettingsExtensions
{
    public static void MergeClaudeDetection(this GuardSettings settings, ClaudeDetectionResult detection)
    {
        settings.ClaudeInstallDirectories = settings.ClaudeInstallDirectories
            .Concat(detection.InstallDirectories)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        settings.ClaudeExecutablePaths = settings.ClaudeExecutablePaths
            .Concat(detection.ExecutablePaths)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}

public sealed class LogService
{
    private readonly object _gate = new();

    public string CurrentLogFile { get; } = Path.Combine(AppPaths.Logs, $"guard-{DateTime.Now:yyyyMMdd}.log");

    public void Info(string message) => Write("INFO", message);
    public void Warn(string message) => Write("WARN", message);
    public void Error(string message) => Write("ERROR", message);

    public void WriteDecision(GuardRuntimeState state)
    {
        var line = string.Join(" | ",
            $"ip={state.Ip.PublicIp}",
            $"country={state.Ip.CountryCode}",
            $"asn={state.Ip.Asn}",
            $"decision={state.Decision.Status}",
            $"reason={state.Decision.Reason}",
            $"claudeRunning={state.Process.IsClaudeRunning}",
            $"pids={string.Join(',', state.Process.Processes.Where(p => p.IsClaudeRelated).Select(p => p.ProcessId))}",
            $"firewall={state.Firewall.RuleStatus}/{state.Firewall.AccessStatus}");
        Write("DECISION", line);
    }

    public IReadOnlyList<string> Tail(int count)
    {
        try
        {
            if (!File.Exists(CurrentLogFile))
            {
                return [];
            }

            return File.ReadLines(CurrentLogFile).TakeLast(count).ToList();
        }
        catch (Exception ex)
        {
            return [$"Unable to read logs: {ex.Message}"];
        }
    }

    private void Write(string level, string message)
    {
        AppPaths.Ensure();
        lock (_gate)
        {
            File.AppendAllText(CurrentLogFile, $"{DateTimeOffset.Now:O} [{level}] {message}{Environment.NewLine}");
        }
    }
}

public static class ClaudeInstallationDetector
{
    private const string UserProvidedClaudeAppPath = @"C:\Program Files\WindowsApps\Claude_1.15962.1.0_x64__pzs8sxrjxfjjc\app";

    public static ClaudeDetectionResult Detect()
    {
        var directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var executables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddDirectoryIfExists(directories, UserProvidedClaudeAppPath);
        AddExecutablesFromDirectory(executables, UserProvidedClaudeAppPath);

        AddExecutableIfExists(executables, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Claude", "Claude.exe"));
        AddExecutableIfExists(executables, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AnthropicClaude", "Claude.exe"));
        AddExecutableIfExists(executables, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Claude", "Claude.exe"));

        foreach (var appxLocation in DetectAppxInstallLocations())
        {
            AddDirectoryIfExists(directories, appxLocation);
            AddDirectoryIfExists(directories, Path.Combine(appxLocation, "app"));
            AddExecutablesFromDirectory(executables, Path.Combine(appxLocation, "app"));
        }

        foreach (var root in new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".vscode", "extensions"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".vscode-insiders", "extensions"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cursor", "extensions"),
            @"C:\Program Files\WindowsApps"
        })
        {
            if (!Directory.Exists(root))
            {
                continue;
            }

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories)
                    .Where(IsClaudeRelatedExecutablePath)
                    .Take(40))
                {
                    AddExecutableIfExists(executables, file);
                    AddDirectoryIfExists(directories, Path.GetDirectoryName(file));
                }
            }
            catch
            {
                // Some application directories are protected or transient.
            }
        }

        return new ClaudeDetectionResult(directories.ToList(), executables.ToList());
    }

    public static string? DetectAppUserModelId()
    {
        var packageFamilyName = DetectAppxPackageFamilyNames().FirstOrDefault();
        return string.IsNullOrWhiteSpace(packageFamilyName) ? null : $"{packageFamilyName}!Claude";
    }

    public static IReadOnlyList<string> FindExecutablesInDirectory(string directory)
    {
        var executables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddExecutablesFromDirectory(executables, directory);
        return executables.ToList();
    }

    private static void AddDirectoryIfExists(HashSet<string> directories, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
        {
            directories.Add(path);
        }
    }

    private static void AddExecutableIfExists(HashSet<string> executables, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path) && IsClaudeRelatedExecutablePath(path))
        {
            executables.Add(path);
        }
    }

    private static void AddExecutablesFromDirectory(HashSet<string> executables, string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return;
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*.exe", SearchOption.AllDirectories).Where(IsClaudeRelatedExecutablePath))
            {
                executables.Add(file);
            }
        }
        catch
        {
            // Protected MSIX folders can deny recursive access.
        }
    }

    private static bool IsClaudeRelatedExecutablePath(string path)
    {
        var normalized = path.Replace('/', '\\');
        var file = Path.GetFileName(normalized);
        if (file.Equals("claude.exe", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return normalized.Contains("\\WindowsApps\\Claude_", StringComparison.OrdinalIgnoreCase)
            && (file.Equals("chrome-native-host.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("cowork-svc.exe", StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> DetectAppxInstallLocations()
    {
        foreach (var location in ReadAppxPackageProperty("InstallLocation"))
        {
            if (Directory.Exists(location))
            {
                yield return location;
            }
        }
    }

    private static IEnumerable<string> DetectAppxPackageFamilyNames()
    {
        foreach (var familyName in ReadAppxPackageProperty("PackageFamilyName"))
        {
            yield return familyName;
        }
    }

    private static IEnumerable<string> ReadAppxPackageProperty(string propertyName)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-AppxPackage -Name Claude | Select-Object -ExpandProperty {propertyName}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });

            if (process is null)
            {
                yield break;
            }

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);
            foreach (var line in output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                yield return line;
            }
        }
        finally
        {
        }
    }
}

public sealed class PublicIpService
{
    private readonly object _clientGate = new();
    private HttpClient _client = CreateClient();

    public void ResetConnections()
    {
        HttpClient oldClient;
        lock (_clientGate)
        {
            oldClient = _client;
            _client = CreateClient();
        }

        oldClient.Dispose();
    }

    public async Task<IpObservation> CheckAsync(CancellationToken cancellationToken)
    {
        var readings = new List<IpProviderReading>
        {
            await ReadIpify(cancellationToken),
            await ReadPlain("api.ip.sb", "https://api.ip.sb/ip", authoritative: true, cancellationToken),
            await ReadPlain("ipinfo.io", "https://ipinfo.io/ip", authoritative: true, cancellationToken),
            await ReadCloudflare(cancellationToken),
            await ReadPlain("ifconfig.me", "https://ifconfig.me/ip", authoritative: false, cancellationToken)
        };

        var selected = IpDecisionModel.SelectAuthoritativeAddress(readings);
        if (selected.Address is null)
        {
            return new IpObservation(null, null, null, null, null, readings, null, false, false, selected.Error);
        }

        readings = AnnotateRouteOutliers(readings, selected.Address);
        if (selected.Mismatch)
        {
            var countryRotation = await TryAcceptSameCountryRotationAsync(readings, selected.Address, cancellationToken);
            if (countryRotation.Accepted)
            {
                readings = AnnotateSameCountryRotation(readings, countryRotation.CountryCode);
                return new IpObservation(
                    selected.Address,
                    countryRotation.CountryCode,
                    countryRotation.CountryName,
                    countryRotation.Asn,
                    countryRotation.Provider,
                    readings,
                    DateTimeOffset.Now,
                    true,
                    false,
                    $"Public IP is rotating inside {countryRotation.CountryName ?? countryRotation.CountryCode}; a more stable VPN/server is recommended.");
            }

            return new IpObservation(selected.Address, null, null, null, null, readings, DateTimeOffset.Now, true, true, selected.Error);
        }

        if (!string.IsNullOrWhiteSpace(selected.Error))
        {
            return new IpObservation(selected.Address, null, null, null, null, readings, DateTimeOffset.Now, false, false, selected.Error);
        }

        var geo = await LookupGeoAsync(selected.Address, cancellationToken);
        return new IpObservation(selected.Address, geo.CountryCode, geo.CountryName, geo.Asn, geo.Provider, readings, DateTimeOffset.Now, geo.Success, false, geo.Error);
    }

    private async Task<IpProviderReading> ReadIpify(CancellationToken cancellationToken)
    {
        try
        {
            using var json = JsonDocument.Parse(await GetStringAsync("https://api.ipify.org?format=json", cancellationToken));
            var ip = json.RootElement.GetProperty("ip").GetString();
            return Parse("api.ipify.org", ip);
        }
        catch (Exception ex)
        {
            return new IpProviderReading("api.ipify.org", null, ex.Message);
        }
    }

    private async Task<IpProviderReading> ReadPlain(string provider, string url, bool authoritative, CancellationToken cancellationToken)
    {
        try
        {
            return Parse(provider, await GetStringAsync(url, cancellationToken), authoritative);
        }
        catch (Exception ex)
        {
            return new IpProviderReading(provider, null, ex.Message, authoritative);
        }
    }

    private async Task<IpProviderReading> ReadCloudflare(CancellationToken cancellationToken)
    {
        try
        {
            var trace = await GetStringAsync("https://cloudflare.com/cdn-cgi/trace", cancellationToken);
            var ip = trace.Split('\n')
                .Select(line => line.Split('=', 2))
                .FirstOrDefault(parts => parts.Length == 2 && parts[0] == "ip")?[1];
            return Parse("cloudflare trace", ip);
        }
        catch (Exception ex)
        {
            return new IpProviderReading("cloudflare trace", null, ex.Message);
        }
    }

    private static IpProviderReading Parse(string provider, string? text, bool authoritative = true)
    {
        var value = (text ?? "").Trim();
        return IPAddress.TryParse(value, out var address)
            ? new IpProviderReading(provider, address, null, authoritative)
            : new IpProviderReading(provider, null, $"Invalid IP response: {value}", authoritative);
    }

    private static List<IpProviderReading> AnnotateRouteOutliers(List<IpProviderReading> readings, IPAddress selectedAddress)
    {
        var comparer = new IpAddressComparer();
        return readings
            .Select(reading =>
            {
                if (reading.Address is null || comparer.Equals(reading.Address, selectedAddress))
                {
                    return reading;
                }

                if (reading.IsAuthoritative && IpDecisionModel.IsSameEgressPool(reading.Address, selectedAddress))
                {
                    return reading with { Error = "same VPN egress pool; accepted as load-balanced NAT" };
                }

                var note = reading.IsAuthoritative
                    ? "route outlier; ignored because a majority of authoritative providers agreed"
                    : "diagnostic split-route result; ignored for Claude-visible IP decision";
                return reading with { Error = string.IsNullOrWhiteSpace(reading.Error) ? note : $"{reading.Error}; {note}" };
            })
            .ToList();
    }

    private static List<IpProviderReading> AnnotateSameCountryRotation(List<IpProviderReading> readings, string? countryCode) =>
        readings
            .Select(reading =>
            {
                if (!reading.IsAuthoritative || reading.Address is null)
                {
                    return reading;
                }

                var note = $"same-country IP rotation ({countryCode ?? "unknown"}); accepted, but a stable VPN/server is recommended";
                return reading with { Error = string.IsNullOrWhiteSpace(reading.Error) ? note : $"{reading.Error}; {note}" };
            })
            .ToList();

    private async Task<(bool Accepted, string? CountryCode, string? CountryName, string? Asn, string? Provider)> TryAcceptSameCountryRotationAsync(
        IReadOnlyList<IpProviderReading> readings,
        IPAddress selectedAddress,
        CancellationToken cancellationToken)
    {
        var addresses = readings
            .Where(reading => reading.IsAuthoritative && reading.Address is not null)
            .Select(reading => reading.Address!)
            .Distinct(new IpAddressComparer())
            .ToList();
        if (addresses.Count < 2)
        {
            return (false, null, null, null, null);
        }

        var geoResults = new List<(IPAddress Address, bool Success, string? CountryCode, string? CountryName, string? Asn, string? Provider)>();
        foreach (var address in addresses)
        {
            var geo = await LookupGeoAsync(address, cancellationToken);
            geoResults.Add((address, geo.Success, geo.CountryCode, geo.CountryName, geo.Asn, geo.Provider));
        }

        var successful = geoResults
            .Where(result => result.Success && !string.IsNullOrWhiteSpace(result.CountryCode))
            .ToList();
        if (successful.Count != addresses.Count)
        {
            return (false, null, null, null, null);
        }

        var countries = successful
            .Select(result => result.CountryCode!.Trim().ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (countries.Count != 1)
        {
            return (false, null, null, null, null);
        }

        var selectedGeo = successful.FirstOrDefault(result => new IpAddressComparer().Equals(result.Address, selectedAddress));
        if (selectedGeo.Address is null)
        {
            selectedGeo = successful[0];
        }

        return (true, selectedGeo.CountryCode, selectedGeo.CountryName, selectedGeo.Asn, selectedGeo.Provider);
    }

    private async Task<(bool Success, string? CountryCode, string? CountryName, string? Asn, string? Provider, string? Error)> LookupGeoAsync(IPAddress address, CancellationToken cancellationToken)
    {
        var whoIs = await LookupIpWhoIs(address, cancellationToken);
        if (whoIs.Success)
        {
            return whoIs;
        }

        var ipApi = await LookupIpApi(address, cancellationToken);
        return ipApi.Success ? ipApi : (false, null, null, null, null, $"{whoIs.Error}; {ipApi.Error}");
    }

    private async Task<(bool Success, string? CountryCode, string? CountryName, string? Asn, string? Provider, string? Error)> LookupIpWhoIs(IPAddress address, CancellationToken cancellationToken)
    {
        try
        {
            using var json = JsonDocument.Parse(await GetStringAsync($"https://ipwho.is/{address}", cancellationToken));
            if (json.RootElement.TryGetProperty("success", out var success) && !success.GetBoolean())
            {
                return (false, null, null, null, null, "ipwho.is lookup failed.");
            }

            var countryCode = json.RootElement.TryGetProperty("country_code", out var countryElement) ? countryElement.GetString() : null;
            var countryName = json.RootElement.TryGetProperty("country", out var countryNameElement) ? countryNameElement.GetString() : null;
            var connection = json.RootElement.TryGetProperty("connection", out var c) ? c : default;
            var asn = connection.ValueKind == JsonValueKind.Object && connection.TryGetProperty("asn", out var asnElement)
                ? $"AS{asnElement.GetInt32()}"
                : null;
            var provider = connection.ValueKind == JsonValueKind.Object && connection.TryGetProperty("org", out var orgElement)
                ? orgElement.GetString()
                : null;
            return (!string.IsNullOrWhiteSpace(countryCode), countryCode, countryName, asn, provider, null);
        }
        catch (Exception ex)
        {
            return (false, null, null, null, null, ex.Message);
        }
    }

    private async Task<(bool Success, string? CountryCode, string? CountryName, string? Asn, string? Provider, string? Error)> LookupIpApi(IPAddress address, CancellationToken cancellationToken)
    {
        try
        {
            using var json = JsonDocument.Parse(await GetStringAsync($"http://ip-api.com/json/{address}?fields=status,country,countryCode,as,isp,message", cancellationToken));
            var status = json.RootElement.GetProperty("status").GetString();
            if (!string.Equals(status, "success", StringComparison.OrdinalIgnoreCase))
            {
                return (false, null, null, null, null, json.RootElement.TryGetProperty("message", out var m) ? m.GetString() : "ip-api lookup failed.");
            }

            var countryCode = json.RootElement.GetProperty("countryCode").GetString();
            var countryName = json.RootElement.TryGetProperty("country", out var countryElement) ? countryElement.GetString() : null;
            var asn = json.RootElement.TryGetProperty("as", out var asElement) ? asElement.GetString()?.Split(' ', 2)[0] : null;
            var provider = json.RootElement.TryGetProperty("isp", out var ispElement) ? ispElement.GetString() : null;
            return (!string.IsNullOrWhiteSpace(countryCode), countryCode, countryName, asn, provider, null);
        }
        catch (Exception ex)
        {
            return (false, null, null, null, null, ex.Message);
        }
    }

    private async Task<string> GetStringAsync(string url, CancellationToken cancellationToken)
    {
        HttpClient client;
        lock (_clientGate)
        {
            client = _client;
        }

        return await client.GetStringAsync(url, cancellationToken);
    }

    private static HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromSeconds(5),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(2),
            ConnectTimeout = TimeSpan.FromSeconds(4)
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(4)
        };
    }
}

public sealed class FirewallService
{
    private readonly LogService _log;
    private FirewallSnapshot _last = new(FirewallRuleStatus.Unknown, FirewallAccessStatus.Unknown, "none", null, DateTimeOffset.Now);
    private string _lastEnabledPathKey = "";

    public FirewallService(LogService log) => _log = log;

    public async Task<FirewallSnapshot> EnableBlockAsync(IEnumerable<string> executablePaths)
    {
        var paths = executablePaths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (paths.Count == 0)
        {
            _last = new FirewallSnapshot(FirewallRuleStatus.Error, FirewallAccessStatus.Unknown, "enable block", "No Claude executable path exists yet.", DateTimeOffset.Now);
            _log.Warn(_last.LastError ?? "No Claude executable path exists yet.");
            return _last;
        }

        var pathKey = string.Join("|", paths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase));
        if (_last.RuleStatus == FirewallRuleStatus.RuleActive
            && _last.AccessStatus == FirewallAccessStatus.Blocked
            && string.Equals(_lastEnabledPathKey, pathKey, StringComparison.OrdinalIgnoreCase))
        {
            return _last with { LastOperation = "enable block skipped: already active", CheckedAt = DateTimeOffset.Now };
        }

        try
        {
            await DeleteOwnRulesAsync();
            for (var i = 0; i < paths.Count; i++)
            {
                var name = i == 0 ? "ClaudeIPGuard_Block_ClaudeDesktop_Main" : $"ClaudeIPGuard_Block_ClaudeDesktop_Helper_{i}";
                var args = $"advfirewall firewall add rule name={name} dir=out action=block program=\"{paths[i]}\" enable=yes profile=any";
                await RunNetshAsync(args);
            }

            _last = new FirewallSnapshot(FirewallRuleStatus.RuleActive, FirewallAccessStatus.Blocked, "enable block", null, DateTimeOffset.Now);
            _lastEnabledPathKey = pathKey;
            _log.Info($"Firewall block enabled for {paths.Count} Claude path(s).");
            return _last;
        }
        catch (Exception ex)
        {
            _last = new FirewallSnapshot(FirewallRuleStatus.Error, FirewallAccessStatus.Unknown, "enable block", ex.Message, DateTimeOffset.Now);
            _log.Error($"Firewall block failed: {ex.Message}");
            return _last;
        }
    }

    public async Task<FirewallSnapshot> DisableBlockIfSafeAsync(bool safe)
    {
        if (!safe)
        {
            return await EnableBlockAsync([]);
        }

        try
        {
            await DeleteOwnRulesAsync();
            _lastEnabledPathKey = "";
            _last = await VerifyAsync();
            if (_last.RuleStatus == FirewallRuleStatus.RuleActive)
            {
                _last = new FirewallSnapshot(FirewallRuleStatus.Error, FirewallAccessStatus.Unknown, "disable block after safe check", "Firewall rules are still active after unblock attempt.", DateTimeOffset.Now);
                _log.Error(_last.LastError ?? "Firewall rules are still active after unblock attempt.");
                return _last;
            }

            _last = _last with { LastOperation = "disable block after safe check" };
            _log.Info("Firewall block disabled and verified after successful safe check.");
            return _last;
        }
        catch (Exception ex)
        {
            _last = new FirewallSnapshot(FirewallRuleStatus.Error, FirewallAccessStatus.Unknown, "disable block", ex.Message, DateTimeOffset.Now);
            _log.Error($"Firewall unblock failed: {ex.Message}");
            return _last;
        }
    }

    public async Task<FirewallSnapshot> VerifyAsync()
    {
        var sawInactiveOwnRule = false;
        foreach (var name in OwnRuleNames())
        {
            var result = await RunNetshResultAsync($"advfirewall firewall show rule name={name}");
            var combined = $"{result.Output}{Environment.NewLine}{result.Error}";
            if (result.ExitCode != 0 && FirewallStateModel.IsRuleMissingOutput(combined))
            {
                continue;
            }

            if (result.ExitCode != 0)
            {
                _last = new FirewallSnapshot(FirewallRuleStatus.Error, FirewallAccessStatus.Unknown, "verify", string.IsNullOrWhiteSpace(result.Error) ? result.Output : result.Error, DateTimeOffset.Now);
                return _last;
            }

            var parsedRule = FirewallStateModel.ParseNetshShowRule(result.ExitCode, result.Output, result.Error, DateTimeOffset.Now);
            if (parsedRule.RuleStatus is FirewallRuleStatus.RuleActive or FirewallRuleStatus.Error)
            {
                _last = parsedRule;
                return _last;
            }

            sawInactiveOwnRule = true;
        }

        var parsed = new FirewallSnapshot(FirewallRuleStatus.RuleInactive, FirewallAccessStatus.Allowed, "verify", null, DateTimeOffset.Now);
        if (!sawInactiveOwnRule
            && parsed.RuleStatus == FirewallRuleStatus.RuleInactive
            && _last.RuleStatus == FirewallRuleStatus.Error
            && (_last.LastOperation.Contains("enable block", StringComparison.OrdinalIgnoreCase)
                || _last.LastOperation.Contains("failed block", StringComparison.OrdinalIgnoreCase)))
        {
            _last = _last with
            {
                LastOperation = "verify after failed block",
                LastError = _last.LastError ?? "Firewall block was requested but no active rule exists.",
                CheckedAt = DateTimeOffset.Now
            };
            return _last;
        }

        _last = parsed;
        return _last;
    }

    private static async Task<string> RunNetshAsync(string args)
    {
        var result = await RunNetshResultAsync(args);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.Error) ? result.Output : result.Error);
        }

        return result.Output;
    }

    private static async Task<(int ExitCode, string Output, string Error)> RunNetshResultAsync(string args)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = args,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        }) ?? throw new InvalidOperationException("Unable to start netsh.");

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, output, error);
    }

    private static async Task DeleteOwnRulesAsync()
    {
        foreach (var name in OwnRuleNames())
        {
            var result = await RunNetshResultAsync($"advfirewall firewall delete rule name={name}");
            var combined = $"{result.Output}{Environment.NewLine}{result.Error}";
            if (result.ExitCode != 0 && FirewallStateModel.IsAccessDeniedOutput(combined))
            {
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.Error) ? result.Output : result.Error);
            }
        }
    }

    private static IEnumerable<string> OwnRuleNames()
    {
        yield return "ClaudeIPGuard_Block_ClaudeDesktop_Main";
        for (var i = 1; i <= 20; i++)
        {
            yield return $"ClaudeIPGuard_Block_ClaudeDesktop_Helper_{i}";
        }
    }
}

public sealed class ClaudeProcessService
{
    public ProcessSnapshot Snapshot(GuardSettings settings)
    {
        var parentMap = NativeProcessParentReader.ReadParentProcessIds();
        var raw = Process.GetProcesses()
            .Select(process =>
            {
                string? path = null;
                try { path = process.MainModule?.FileName; } catch { }
                parentMap.TryGetValue(process.Id, out var parentId);
                return new ProcessInfo(process.Id, parentId == 0 ? null : parentId, process.ProcessName, path, null, false);
            })
            .ToList();

        var claudeIds = new HashSet<int>();
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var info in raw)
            {
                if (claudeIds.Contains(info.ProcessId))
                {
                    continue;
                }

                if (ProcessClassifier.IsClaudeRelated(info.Name, info.ExecutablePath, info.CommandLine, settings.ClaudeExecutablePaths, claudeIds, info.ParentProcessId))
                {
                    claudeIds.Add(info.ProcessId);
                    changed = true;
                }
            }
        }

        return new ProcessSnapshot(raw.Select(p => p with { IsClaudeRelated = claudeIds.Contains(p.ProcessId) }).ToList(), DateTimeOffset.Now);
    }

    public async Task<int> KillClaudeAsync(GuardSettings settings, FirewallService firewall, LogService log)
    {
        await firewall.EnableBlockAsync(settings.ClaudeExecutablePaths);
        var snapshot = Snapshot(settings);
        var targets = snapshot.Processes.Where(p => p.IsClaudeRelated).OrderByDescending(p => p.ParentProcessId.HasValue).ToList();
        var killed = 0;

        foreach (var target in targets)
        {
            try
            {
                using var process = Process.GetProcessById(target.ProcessId);
                process.Kill(entireProcessTree: true);
                killed++;
                log.Warn($"Killed Claude-related process pid={target.ProcessId} name={target.Name} path={target.ExecutablePath}");
            }
            catch (Exception ex)
            {
                log.Error($"Unable to kill pid={target.ProcessId}: {ex.Message}");
            }
        }

        await Task.Delay(500);
        return killed;
    }
}

public static class NativeProcessParentReader
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    public static Dictionary<int, int> ReadParentProcessIds()
    {
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        var map = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            return map;
        }

        try
        {
            var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32First(snapshot, ref entry))
            {
                return map;
            }

            do
            {
                map[(int)entry.th32ProcessID] = (int)entry.th32ParentProcessID;
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return map;
    }
}

public sealed class DiagnosticReportService
{
    private readonly LogService _log;

    public DiagnosticReportService(LogService log) => _log = log;

    public string Export(GuardRuntimeState state, GuardSettings settings)
    {
        AppPaths.Ensure();
        var file = Path.Combine(AppPaths.Diagnostics, $"diagnostic-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
        var sb = new StringBuilder();
        sb.AppendLine("Claude IP Guard Diagnostic Report");
        sb.AppendLine($"Generated: {DateTimeOffset.Now:O}");
        sb.AppendLine($"App version: {typeof(App).Assembly.GetName().Version}");
        sb.AppendLine($"Windows version: {Environment.OSVersion}");
        sb.AppendLine($"Current mode: {settings.Mode}");
        sb.AppendLine($"Current IP: {state.Ip.PublicIp}");
        sb.AppendLine($"Country: {state.Ip.CountryCode}");
        sb.AppendLine($"ASN/provider: {state.Ip.Asn} {state.Ip.Provider}");
        sb.AppendLine($"Claude executable paths: {string.Join("; ", settings.ClaudeExecutablePaths)}");
        sb.AppendLine($"Claude running: {state.Process.IsClaudeRunning}");
        sb.AppendLine($"Claude process count: {state.Process.ClaudeProcessCount}");
        sb.AppendLine($"Firewall status: {state.Firewall.RuleStatus}/{state.Firewall.AccessStatus}");
        sb.AppendLine($"Decision: {state.Decision.Status} - {state.Decision.Reason}");
        sb.AppendLine();
        sb.AppendLine("Recent decision log and errors:");
        foreach (var line in _log.Tail(80))
        {
            sb.AppendLine(line);
        }

        File.WriteAllText(file, sb.ToString());
        _log.Info($"Diagnostic report exported: {file}");
        return file;
    }
}

public sealed class TrayService : IDisposable
{
    private readonly Forms.NotifyIcon _notifyIcon;
    private readonly System.Drawing.Icon? _icon;

    public TrayService(
        Action openDashboard,
        Action openClaudeSafely,
        Action checkNow,
        Action killClaude,
        Action blockNetwork,
        Action recheckUnblock,
        Action openSettings,
        Action openLogs,
        Action exit)
    {
        _icon = LoadTrayIcon();
        _notifyIcon = new Forms.NotifyIcon
        {
            Icon = _icon ?? System.Drawing.SystemIcons.Application,
            Text = "Claude IP Guard",
            Visible = true,
            ContextMenuStrip = new Forms.ContextMenuStrip()
        };

        _notifyIcon.DoubleClick += (_, _) => openDashboard();
        Add("Open Dashboard", openDashboard);
        Add("Open Claude Safely", openClaudeSafely);
        Add("Check IP Now", checkNow);
        Add("Kill Claude", killClaude);
        Add("Block Claude Network", blockNetwork);
        Add("Re-check and unblock if safe", recheckUnblock);
        Add("Settings", openSettings);
        Add("Logs", openLogs);
        Add("Exit", exit);
    }

    public void ShowDanger(string title, string text)
    {
        _notifyIcon.ShowBalloonTip(8000, title, text, Forms.ToolTipIcon.Warning);
    }

    public void SetText(string text)
    {
        _notifyIcon.Text = text.Length > 63 ? text[..63] : text;
    }

    public void Dispose()
    {
        _notifyIcon.Dispose();
        _icon?.Dispose();
    }

    private void Add(string text, Action action)
    {
        var item = new Forms.ToolStripMenuItem(text);
        item.Click += (_, _) => action();
        _notifyIcon.ContextMenuStrip!.Items.Add(item);
    }

    private static System.Drawing.Icon? LoadTrayIcon()
    {
        try
        {
            var processPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(processPath) && File.Exists(processPath))
            {
                return System.Drawing.Icon.ExtractAssociatedIcon(processPath);
            }
        }
        catch
        {
            return null;
        }

        return null;
    }
}
