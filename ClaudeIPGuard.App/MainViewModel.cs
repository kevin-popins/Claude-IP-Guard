using ClaudeIPGuard.Core;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Windows;
using Forms = System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Threading;

namespace ClaudeIPGuard.App;

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly SettingsStore _settingsStore = new();
    private readonly LogService _log = new();
    private readonly PublicIpService _ipService = new();
    private readonly FirewallService _firewall;
    private readonly ClaudeProcessService _processService = new();
    private readonly DecisionEngine _decisionEngine = new();
    private readonly DiagnosticReportService _diagnostics;
    private readonly DispatcherTimer _uiTimer = new();
    private readonly DispatcherTimer _processTimer = new();
    private readonly DispatcherTimer _ipTimer = new();
    private readonly DispatcherTimer _toastTimer = new();
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly object _networkChangeGate = new();
    private readonly Action _bringToFront;
    private readonly Action<DangerWarning> _showWarning;
    private readonly Action _showSettings;

    private GuardSettings _settings;
    private TrayService? _tray;
    private GuardRuntimeState? _state;
    private CancellationTokenSource? _networkChangeCts;
    private bool _networkChangedPending;
    private bool _pendingForceIpCheck;
    private DateTimeOffset _lastFirewallBlockAttempt = DateTimeOffset.MinValue;
    private string _modeSelection = "Block countries";
    private string _status = "UNKNOWN";
    private string _statusDetail = "Blocked until verified.";
    private string _statusBrush = "#F4C542";
    private string _statusLogoPath = AppLogoPaths.Safe;
    private string _currentIp = "unknown";
    private string _country = "unknown";
    private string _asnProvider = "unknown";
    private string _claudeVisibleIp = "unknown";
    private string _claudeStatus = "not running";
    private string _claudeProcessCount = "0";
    private string _claudePath = "not detected";
    private string _networkAccess = "blocked";
    private string _firewallStatus = "unknown";
    private string _lastIpCheck = "never";
    private string _lastNetworkChange = "never";
    private string _lastDecision = "Blocked until verified.";
    private string _monitoringStatus = "active";
    private string _strictMode = "enabled";
    private string _firewallLastOperation = "none";
    private string _firewallLastError = "";
    private string _toastMessage = "";
    private string _toastBrush = "#0969DA";
    private bool _toastVisible;
    private string _blockedCountriesText = "";
    private string _allowlistText = "";
    private string _pathsText = "";
    private string _installFoldersText = "";
    private string _intervalText = "5";
    private string _logFolder = AppPaths.Logs;
    private bool _settingsStrictMode;
    private bool _settingsStartWithWindows;
    private bool _settingsStartMinimized;
    private bool _settingsNotifications;
    private bool _settingsBringToFront;

    public MainViewModel(Action bringToFront, Action<DangerWarning> showWarning, Action showSettings)
    {
        _bringToFront = bringToFront;
        _showWarning = showWarning;
        _showSettings = showSettings;
        _settings = _settingsStore.Load();
        _firewall = new FirewallService(_log);
        _diagnostics = new DiagnosticReportService(_log);
        SyncSettingsToUi();

        OpenClaudeSafelyCommand = new AsyncRelayCommand(OpenClaudeSafelyAsync);
        CheckNowCommand = new AsyncRelayCommand(CheckNowAsync);
        KillClaudeCommand = new AsyncRelayCommand(KillClaudeAsync);
        BlockNetworkCommand = new AsyncRelayCommand(BlockNetworkAsync);
        RecheckUnblockCommand = new AsyncRelayCommand(RecheckAndUnblockAsync);
        SaveSettingsCommand = new RelayCommand(SaveSettings);
        ExportReportCommand = new RelayCommand(ExportReport);
        OpenLogsCommand = new RelayCommand(OpenLogs);
        AutoDetectClaudeCommand = new RelayCommand(AutoDetectClaude);
        AddClaudeFolderCommand = new RelayCommand(AddClaudeFolder);
        AddClaudeExecutableCommand = new RelayCommand(AddClaudeExecutable);
        ClearLogsCommand = new RelayCommand(ClearLogs);
        RepairFirewallCommand = new AsyncRelayCommand(RepairFirewallAsync);
        TestFirewallCommand = new AsyncRelayCommand(TestFirewallAsync);

        _toastTimer.Interval = TimeSpan.FromSeconds(5);
        _toastTimer.Tick += (_, _) =>
        {
            _toastTimer.Stop();
            ToastVisible = false;
        };
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<string> RecentLogs { get; } = [];
    public ObservableCollection<string> ProviderReadings { get; } = [];
    public ObservableCollection<string> FirewallRules { get; } = [];

    public ICommand OpenClaudeSafelyCommand { get; }
    public ICommand CheckNowCommand { get; }
    public ICommand KillClaudeCommand { get; }
    public ICommand BlockNetworkCommand { get; }
    public ICommand RecheckUnblockCommand { get; }
    public ICommand SaveSettingsCommand { get; }
    public ICommand ExportReportCommand { get; }
    public ICommand OpenLogsCommand { get; }
    public ICommand AutoDetectClaudeCommand { get; }
    public ICommand AddClaudeFolderCommand { get; }
    public ICommand AddClaudeExecutableCommand { get; }
    public ICommand ClearLogsCommand { get; }
    public ICommand RepairFirewallCommand { get; }
    public ICommand TestFirewallCommand { get; }

    public string Status { get => _status; private set => Set(ref _status, value); }
    public string StatusDetail { get => _statusDetail; private set => Set(ref _statusDetail, value); }
    public string StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }
    public string StatusLogoPath { get => _statusLogoPath; private set => Set(ref _statusLogoPath, value); }
    public string CurrentIp { get => _currentIp; private set => Set(ref _currentIp, value); }
    public string Country { get => _country; private set => Set(ref _country, value); }
    public string AsnProvider { get => _asnProvider; private set => Set(ref _asnProvider, value); }
    public string ClaudeVisibleIp { get => _claudeVisibleIp; private set => Set(ref _claudeVisibleIp, value); }
    public string ClaudeStatus { get => _claudeStatus; private set => Set(ref _claudeStatus, value); }
    public string ClaudeProcessCount { get => _claudeProcessCount; private set => Set(ref _claudeProcessCount, value); }
    public string ClaudePath { get => _claudePath; private set => Set(ref _claudePath, value); }
    public string NetworkAccess { get => _networkAccess; private set => Set(ref _networkAccess, value); }
    public string FirewallStatus { get => _firewallStatus; private set => Set(ref _firewallStatus, value); }
    public string LastIpCheck { get => _lastIpCheck; private set => Set(ref _lastIpCheck, value); }
    public string LastNetworkChange { get => _lastNetworkChange; private set => Set(ref _lastNetworkChange, value); }
    public string LastDecision { get => _lastDecision; private set => Set(ref _lastDecision, value); }
    public string MonitoringStatusText { get => _monitoringStatus; private set => Set(ref _monitoringStatus, value); }
    public string StrictModeText { get => _strictMode; private set => Set(ref _strictMode, value); }
    public string FirewallLastOperation { get => _firewallLastOperation; private set => Set(ref _firewallLastOperation, value); }
    public string FirewallLastError { get => _firewallLastError; private set => Set(ref _firewallLastError, value); }
    public string ToastMessage { get => _toastMessage; private set => Set(ref _toastMessage, value); }
    public string ToastBrush { get => _toastBrush; private set => Set(ref _toastBrush, value); }
    public bool ToastVisible { get => _toastVisible; private set => Set(ref _toastVisible, value); }
    public string BlockedCountriesText { get => _blockedCountriesText; set => Set(ref _blockedCountriesText, value); }
    public string AllowlistText { get => _allowlistText; set => Set(ref _allowlistText, value); }
    public string PathsText { get => _pathsText; set => Set(ref _pathsText, value); }
    public string InstallFoldersText { get => _installFoldersText; set => Set(ref _installFoldersText, value); }
    public string IntervalText { get => _intervalText; set => Set(ref _intervalText, value); }
    public string LogFolder { get => _logFolder; private set => Set(ref _logFolder, value); }
    public string ModeSelection { get => _modeSelection; set => Set(ref _modeSelection, value); }
    public bool SettingsStrictMode { get => _settingsStrictMode; set => Set(ref _settingsStrictMode, value); }
    public bool SettingsStartWithWindows { get => _settingsStartWithWindows; set => Set(ref _settingsStartWithWindows, value); }
    public bool SettingsStartMinimized { get => _settingsStartMinimized; set => Set(ref _settingsStartMinimized, value); }
    public bool SettingsNotifications { get => _settingsNotifications; set => Set(ref _settingsNotifications, value); }
    public bool SettingsBringToFront { get => _settingsBringToFront; set => Set(ref _settingsBringToFront, value); }

    public async Task StartAsync()
    {
        AppPaths.Ensure();
        _log.Info("Claude IP Guard started.");
        AutoDetectClaude(saveImmediately: true);

        _tray = new TrayService(
            () => _bringToFront(),
            () => _ = OpenClaudeSafelyAsync(),
            () => _ = RefreshAsync(forceIpCheck: true, reason: "tray check now"),
            () => _ = KillClaudeAsync(),
            () => _ = BlockNetworkAsync(),
            () => _ = RecheckAndUnblockAsync(),
            () => _showSettings(),
            OpenLogs,
            () => System.Windows.Application.Current.Shutdown());

        NetworkChange.NetworkAddressChanged += OnNetworkChanged;

        _uiTimer.Interval = TimeSpan.FromSeconds(Math.Max(1, _settings.UiRefreshIntervalSeconds));
        _uiTimer.Tick += (_, _) => RefreshLogsOnly();
        _uiTimer.Start();

        _processTimer.Interval = TimeSpan.FromSeconds(Math.Max(1, _settings.ProcessMonitorIntervalSeconds));
        _processTimer.Tick += (_, _) => _ = Task.Run(() => RefreshAsync(forceIpCheck: false, reason: "process/firewall timer"));
        _processTimer.Start();

        _ipTimer.Interval = TimeSpan.FromSeconds(Math.Max(1, _settings.IpCheckIntervalSeconds));
        _ipTimer.Tick += (_, _) => _ = Task.Run(() => RefreshAsync(forceIpCheck: true, reason: "ip timer"));
        _ipTimer.Start();

        await EnableFirewallBlockWithBackoffAsync(force: true);
        await RefreshAsync(forceIpCheck: true, reason: "startup");
    }

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        lock (_networkChangeGate)
        {
            _networkChangeCts?.Cancel();
            _networkChangeCts?.Dispose();
            _networkChangeCts = null;
        }

        _tray?.Dispose();
        _toastTimer.Stop();
    }

    private async Task RefreshAsync(bool forceIpCheck, string reason)
    {
        if (!await _refreshGate.WaitAsync(0))
        {
            if (forceIpCheck)
            {
                _pendingForceIpCheck = true;
            }

            return;
        }

        try
        {
            if (_networkChangedPending && _settings.BlockImmediatelyOnNetworkChange)
            {
                await _firewall.EnableBlockAsync(_settings.ClaudeExecutablePaths);
            }

            var process = _processService.Snapshot(_settings);
            var firewall = await _firewall.VerifyAsync();
            var ip = _state?.Ip ?? IpObservation.Unknown("Blocked until first verification.");

            if (forceIpCheck || _networkChangedPending)
            {
                if (_state is null)
                {
                    await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        Status = "CHECKING - verifying IP";
                        StatusDetail = "Verifying current public IP.";
                        StatusBrush = "#F4C542";
                        StatusLogoPath = AppLogoPaths.ConnectionBlocked;
                    });
                }

                ip = await _ipService.CheckAsync(CancellationToken.None);
            }

            var networkChanged = _networkChangedPending && (!forceIpCheck || !ip.CheckSucceeded);
            var wasClaudeUserAppRunning = process.IsClaudeUserAppRunning;
            var decision = _decisionEngine.Evaluate(_settings, ip, firewall, process, networkChanged);

            if (decision.ShouldBlockNetwork)
            {
                firewall = await EnableFirewallBlockWithBackoffAsync(force: networkChanged || reason.Contains("startup", StringComparison.OrdinalIgnoreCase));
            }
            else if (decision.FirewallCommand == FirewallCommand.AllowIfVerifiedSafe
                && firewall.RuleStatus == FirewallRuleStatus.RuleActive)
            {
                firewall = await _firewall.DisableBlockIfSafeAsync(safe: true);
            }

            if (decision.ShouldKillClaude)
            {
                await _processService.KillClaudeAsync(_settings, _firewall, _log);
                process = _processService.Snapshot(_settings);
            }

            _state = new GuardRuntimeState(ip, process, firewall, decision, MonitoringStatus.Active, _state?.LastNetworkChange, DateTimeOffset.Now);
            _networkChangedPending = false;
            await System.Windows.Application.Current.Dispatcher.InvokeAsync(() => ApplyStateToUi(_state));
            _log.WriteDecision(_state);

            if (decision.Status is SafetyStatus.Danger && wasClaudeUserAppRunning)
            {
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(() => TriggerDangerWarning(_state));
            }
        }
        catch (Exception ex)
        {
            _log.Error($"Refresh failed ({reason}): {ex.Message}");
            var process = _processService.Snapshot(_settings);
            var firewall = await EnableFirewallBlockWithBackoffAsync(force: false);
            var ip = IpObservation.Unknown(ex.Message);
            var decision = _decisionEngine.Evaluate(_settings, ip, firewall, process, networkChanged: false);
            _state = new GuardRuntimeState(ip, process, firewall, decision, MonitoringStatus.Error, _state?.LastNetworkChange, DateTimeOffset.Now);
            await System.Windows.Application.Current.Dispatcher.InvokeAsync(() => ApplyStateToUi(_state));
        }
        finally
        {
            _refreshGate.Release();
            if (_pendingForceIpCheck)
            {
                _pendingForceIpCheck = false;
                _ = Task.Run(() => RefreshAsync(forceIpCheck: true, reason: "queued ip check"));
            }
        }
    }

    private async Task CheckNowAsync()
    {
        ShowToast("Checking public IP...", ToastKind.Info, autoDismiss: false);
        await RefreshAsync(forceIpCheck: true, reason: "manual check");
        ShowToast(DescribeCurrentState("IP check complete"), ToastKindForCurrentState());
    }

    private async Task OpenClaudeSafelyAsync()
    {
        ShowToast("Checking IP before opening Claude...", ToastKind.Info, autoDismiss: false);
        await EnableFirewallBlockWithBackoffAsync(force: true);
        await RefreshAsync(forceIpCheck: true, reason: "open Claude safely");

        if (_state?.Decision.Status == SafetyStatus.Safe)
        {
            var path = _settings.ClaudeExecutablePaths.FirstOrDefault(File.Exists);
            if (path is null)
            {
                _log.Error("Open Claude Safely failed: executable path is not configured.");
                ShowToast("Open Claude failed: executable path is not configured.", ToastKind.Error);
                return;
            }

            LaunchClaude(path);
            _log.Info($"Claude launched safely: {path}");
            await RefreshAsync(forceIpCheck: false, reason: "post launch");
            ShowToast("Claude opened after a safe IP check.", ToastKind.Success);
        }
        else
        {
            _showWarning(DangerWarning.UnsafeBlocked("Unsafe IP detected. Claude network access has been blocked."));
            ShowToast(DescribeCurrentState("Claude was not opened"), ToastKind.Error);
        }
    }

    private static void LaunchClaude(string executablePath)
    {
        var appUserModelId = executablePath.Contains("\\WindowsApps\\Claude_", StringComparison.OrdinalIgnoreCase)
            ? ClaudeInstallationDetector.DetectAppUserModelId()
            : null;

        if (!string.IsNullOrWhiteSpace(appUserModelId))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"shell:AppsFolder\\{appUserModelId}") { UseShellExecute = true });
            return;
        }

        Process.Start(new ProcessStartInfo(executablePath) { UseShellExecute = true });
    }

    private async Task KillClaudeAsync()
    {
        ShowToast("Blocking network and killing Claude-related processes...", ToastKind.Info, autoDismiss: false);
        var killed = await _processService.KillClaudeAsync(_settings, _firewall, _log);
        _log.Warn($"Kill Claude completed. Processes targeted: {killed}. Network access blocked.");
        await RefreshAsync(forceIpCheck: false, reason: "kill Claude");
        LastDecision = "Claude killed. Network access blocked.";
        ShowToast($"Kill Claude complete. Processes targeted: {killed}. Network access blocked.", ToastKind.Success);
    }

    private async Task BlockNetworkAsync()
    {
        ShowToast("Blocking Claude network access...", ToastKind.Info, autoDismiss: false);
        await EnableFirewallBlockWithBackoffAsync(force: true);
        await RefreshAsync(forceIpCheck: false, reason: "manual block");
        ShowToast("Claude network access is blocked.", ToastKind.Success);
    }

    private async Task RecheckAndUnblockAsync()
    {
        ShowToast("Re-checking IP and firewall state...", ToastKind.Info, autoDismiss: false);
        await EnableFirewallBlockWithBackoffAsync(force: true);
        await RefreshAsync(forceIpCheck: true, reason: "recheck and unblock");
        ShowToast(DescribeCurrentState("Re-check complete"), ToastKindForCurrentState());
    }

    private async Task RepairFirewallAsync()
    {
        ShowToast("Repairing firewall rules...", ToastKind.Info, autoDismiss: false);
        await EnableFirewallBlockWithBackoffAsync(force: true);
        await RefreshAsync(forceIpCheck: false, reason: "repair firewall");
        ShowToast("Firewall rules repaired and Claude network is blocked until verification.", ToastKind.Success);
    }

    private async Task TestFirewallAsync()
    {
        ShowToast("Testing firewall block...", ToastKind.Info, autoDismiss: false);
        var before = await EnableFirewallBlockWithBackoffAsync(force: true);
        _log.Info($"Firewall test result: {before.RuleStatus}/{before.AccessStatus} {before.LastError}");
        await RefreshAsync(forceIpCheck: false, reason: "test firewall");
        ShowToast($"Firewall test complete: {before.RuleStatus}/{before.AccessStatus}.", before.AccessStatus == FirewallAccessStatus.Blocked ? ToastKind.Success : ToastKind.Warning);
    }

    private void SaveSettings()
    {
        _settings.Mode = ModeSelection.StartsWith("IP", StringComparison.OrdinalIgnoreCase) ? ProtectionMode.IpAllowlist : ProtectionMode.BlockCountries;
        _settings.BlockedCountries = Lines(BlockedCountriesText).Select(c => c.Trim().ToUpperInvariant()).Where(c => c.Length == 2).ToList();
        _settings.AllowedIpCidrs = Lines(AllowlistText).ToList();
        _settings.ClaudeExecutablePaths = Lines(PathsText).ToList();
        _settings.ClaudeInstallDirectories = Lines(InstallFoldersText).ToList();
        _settings.StrictMode = SettingsStrictMode;
        _settings.StartWithWindows = SettingsStartWithWindows;
        _settings.StartMinimizedToTray = SettingsStartMinimized;
        _settings.ShowWindowsNotifications = SettingsNotifications;
        _settings.BringAppToFrontOnDanger = SettingsBringToFront;
        _settings.IpCheckIntervalSeconds = int.TryParse(IntervalText, out var interval) ? Math.Clamp(interval, 2, 3600) : 5;
        _settingsStore.Save(_settings);
        _ipTimer.Interval = TimeSpan.FromSeconds(_settings.IpCheckIntervalSeconds);
        SyncSettingsToUi();
        _log.Info("Settings saved.");
        ShowToast("Settings saved.", ToastKind.Success);
    }

    private void AutoDetectClaude() => AutoDetectClaude(saveImmediately: false);

    private void AutoDetectClaude(bool saveImmediately)
    {
        var detected = ClaudeInstallationDetector.Detect();
        _settings.MergeClaudeDetection(detected);
        SyncSettingsToUi();
        if (saveImmediately)
        {
            _settingsStore.Save(_settings);
        }

        _log.Info($"Auto-detected {detected.ExecutablePaths.Count} Claude executable path(s) and {detected.InstallDirectories.Count} install folder(s).");
        if (!saveImmediately)
        {
            ShowToast($"Auto-detect complete: {detected.ExecutablePaths.Count} executable path(s) found.", ToastKind.Success);
        }
    }

    private void AddClaudeFolder()
    {
        using var dialog = new Forms.FolderBrowserDialog
        {
            Description = "Select the Claude Desktop installation folder",
            UseDescriptionForTitle = true,
            SelectedPath = Lines(InstallFoldersText).FirstOrDefault(Directory.Exists) ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
        };

        if (dialog.ShowDialog() != Forms.DialogResult.OK)
        {
            return;
        }

        var folder = dialog.SelectedPath;
        var executables = ClaudeInstallationDetector.FindExecutablesInDirectory(folder);
        InstallFoldersText = string.Join(Environment.NewLine, Lines(InstallFoldersText).Append(folder).Distinct(StringComparer.OrdinalIgnoreCase));
        PathsText = string.Join(Environment.NewLine, Lines(PathsText).Concat(executables).Distinct(StringComparer.OrdinalIgnoreCase));
        _log.Info($"Claude folder selected: {folder}; executable matches: {executables.Count}.");
        ShowToast($"Folder added. Claude executable matches: {executables.Count}.", executables.Count > 0 ? ToastKind.Success : ToastKind.Warning);
    }

    private void AddClaudeExecutable()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select Claude executable",
            Filter = "Executable files (*.exe)|*.exe",
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        PathsText = string.Join(Environment.NewLine, Lines(PathsText).Append(dialog.FileName).Distinct(StringComparer.OrdinalIgnoreCase));
        var directory = Path.GetDirectoryName(dialog.FileName);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            InstallFoldersText = string.Join(Environment.NewLine, Lines(InstallFoldersText).Append(directory).Distinct(StringComparer.OrdinalIgnoreCase));
        }

        _log.Info($"Claude executable selected: {dialog.FileName}.");
        ShowToast("Claude executable added.", ToastKind.Success);
    }

    private void ExportReport()
    {
        if (_state is null)
        {
            ShowToast("Diagnostic report is not available until the first guard state is created.", ToastKind.Warning);
            return;
        }

        var file = _diagnostics.Export(_state, _settings);
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{file}\"") { UseShellExecute = true });
        ShowToast("Diagnostic report exported.", ToastKind.Success);
    }

    private void OpenLogs()
    {
        AppPaths.Ensure();
        Process.Start(new ProcessStartInfo(AppPaths.Logs) { UseShellExecute = true });
        ShowToast("Logs folder opened.", ToastKind.Success);
    }

    private void ClearLogs()
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(AppPaths.Logs, "*.log"))
            {
                File.Delete(file);
            }

            RecentLogs.Clear();
            ShowToast("Logs cleared.", ToastKind.Success);
        }
        catch (Exception ex)
        {
            _log.Error($"Unable to clear logs: {ex.Message}");
            ShowToast($"Unable to clear logs: {ex.Message}", ToastKind.Error);
        }
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        if (!_settings.NetworkChangeEventsEnabled)
        {
            return;
        }

        _networkChangedPending = true;
        var lastChange = DateTimeOffset.Now;
        _ipService.ResetConnections();
        CancellationTokenSource cts;
        lock (_networkChangeGate)
        {
            _networkChangeCts?.Cancel();
            _networkChangeCts?.Dispose();
            _networkChangeCts = new CancellationTokenSource();
            cts = _networkChangeCts;
        }

        if (_state is not null)
        {
            _state = _state with
            {
                Ip = IpObservation.Unknown("Network changed; waiting for VPN route to settle."),
                LastNetworkChange = lastChange
            };
        }

        _log.Warn("Network change detected. Blocking Claude before verification and scheduling settled IP checks.");
        _ = System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
        {
            LastNetworkChange = lastChange.ToString("G");
            CurrentIp = "checking";
            ClaudeVisibleIp = "checking";
            Country = "checking";
            Status = "BLOCKED - network changed";
            StatusDetail = "Claude is blocked while the VPN route settles and the public IP is re-checked.";
            StatusBrush = "#D29922";
            StatusLogoPath = AppLogoPaths.ConnectionBlocked;
        });

        _ = Task.Run(() => HandleNetworkChangeVerificationAsync(cts.Token));
    }

    private async Task HandleNetworkChangeVerificationAsync(CancellationToken cancellationToken)
    {
        try
        {
            await EnableFirewallBlockWithBackoffAsync(force: true);
            await RefreshAsync(forceIpCheck: false, reason: "network changed: block first");

            var attempt = 0;
            foreach (var delay in NetworkChangeRetryPolicy.VerificationDelays)
            {
                attempt++;
                await Task.Delay(delay, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();

                _networkChangedPending = true;
                _ipService.ResetConnections();
                _log.Info($"Network change settled IP check attempt {attempt} after {delay.TotalSeconds:0}s.");
                await RefreshAsync(forceIpCheck: true, reason: $"network changed settled check {attempt}");

                if (_state?.Decision.Status == SafetyStatus.Safe)
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            _log.Info("Network change verification superseded by a newer network event.");
        }
        catch (Exception ex)
        {
            _log.Error($"Network change verification failed: {ex.Message}");
        }
    }

    private async Task<FirewallSnapshot> EnableFirewallBlockWithBackoffAsync(bool force)
    {
        var previous = _state?.Firewall;
        var recentFailedAttempt = previous?.RuleStatus == FirewallRuleStatus.Error
            && DateTimeOffset.Now - _lastFirewallBlockAttempt < TimeSpan.FromSeconds(15);

        if (!force && recentFailedAttempt)
        {
            return previous!;
        }

        _lastFirewallBlockAttempt = DateTimeOffset.Now;
        return await _firewall.EnableBlockAsync(_settings.ClaudeExecutablePaths);
    }

    private void TriggerDangerWarning(GuardRuntimeState state)
    {
        var text = $"Unsafe IP detected: {state.Ip.PublicIp}, country {FormatCountry(state.Ip)}. Claude network access was blocked immediately. Reason: {state.Decision.Reason}";
        if (_settings.ShowWindowsNotifications)
        {
            _tray?.ShowDanger("Claude IP Guard", text);
        }

        if (_settings.BringAppToFrontOnDanger)
        {
            _bringToFront();
        }

        if (state.Decision.ShouldKillClaude && !state.Process.IsClaudeUserAppRunning)
        {
            _showWarning(DangerWarning.ClaudeKilled(
                $"Claude Desktop has already been terminated. Network access remains blocked. Reason: {state.Decision.Reason}"));
            return;
        }

        _showWarning(DangerWarning.UnsafeBlocked("Unsafe IP detected. Claude network access has been blocked."));
    }

    private void ApplyStateToUi(GuardRuntimeState state)
    {
        Status = FormatStatus(state);
        StatusBrush = state.Decision.Status switch
        {
            SafetyStatus.Safe => "#238636",
            SafetyStatus.Danger => "#DA3633",
            SafetyStatus.Blocked => "#DA3633",
            SafetyStatus.Checking => "#F4C542",
            _ => "#D29922"
        };
        StatusLogoPath = AppLogoPaths.ForState(state);
        StatusDetail = FormatStatusDetail(state);
        CurrentIp = state.Ip.PublicIp?.ToString() ?? "unknown";
        ClaudeVisibleIp = CurrentIp;
        Country = FormatCountry(state.Ip);
        AsnProvider = string.Join(" ", new[] { state.Ip.Asn, state.Ip.Provider }.Where(s => !string.IsNullOrWhiteSpace(s))).Trim();
        if (string.IsNullOrWhiteSpace(AsnProvider))
        {
            AsnProvider = "unknown";
        }

        ClaudeStatus = state.Process.IsClaudeUserAppRunning ? "running" : "not running";
        ClaudeProcessCount = $"{state.Process.ClaudeUserAppProcessCount} app / {state.Process.ClaudeHelperProcessCount} helper";
        var configuredClaudePath = _settings.ClaudeExecutablePaths.FirstOrDefault(path => path.EndsWith("claude.exe", StringComparison.OrdinalIgnoreCase) && File.Exists(path))
            ?? _settings.ClaudeExecutablePaths.FirstOrDefault(File.Exists);
        ClaudePath = configuredClaudePath
            ?? (string.IsNullOrWhiteSpace(state.Process.ClaudeExecutablePath) ? "not detected" : state.Process.ClaudeExecutablePath);
        NetworkAccess = state.Firewall.AccessStatus == FirewallAccessStatus.Blocked || state.Decision.ShouldBlockNetwork ? "blocked" : "allowed";
        FirewallStatus = state.Firewall.RuleStatus.ToString();
        FirewallLastOperation = state.Firewall.LastOperation;
        FirewallLastError = state.Firewall.LastError ?? "";
        LastIpCheck = state.Ip.LastSuccessfulCheck?.ToString("G") ?? "never";
        LastNetworkChange = state.LastNetworkChange?.ToString("G") ?? LastNetworkChange;
        LastDecision = FormatLastDecision(state);
        MonitoringStatusText = state.MonitoringStatus.ToString().ToLowerInvariant();
        StrictModeText = _settings.StrictMode ? "enabled" : "disabled";
        _tray?.SetText($"Claude IP Guard: {Status}");

        ProviderReadings.Clear();
        foreach (var reading in state.Ip.ProviderReadings)
        {
            var role = reading.IsAuthoritative ? "check" : "diagnostic";
            ProviderReadings.Add($"[{role}] {reading.Provider}: {(reading.Address?.ToString() ?? "error")} {reading.Error}");
        }

        FirewallRules.Clear();
        FirewallRules.Add($"Rule exists/enabled: {state.Firewall.RuleStatus}");
        FirewallRules.Add($"Claude network access: {state.Firewall.AccessStatus}");
        FirewallRules.Add($"Last operation: {state.Firewall.LastOperation}");
        if (!string.IsNullOrWhiteSpace(state.Firewall.LastError))
        {
            FirewallRules.Add($"Last error: {state.Firewall.LastError}");
        }
    }

    private void SyncSettingsToUi()
    {
        ModeSelection = _settings.Mode == ProtectionMode.IpAllowlist ? "IP allowlist" : "Block countries";
        BlockedCountriesText = string.Join(Environment.NewLine, _settings.BlockedCountries);
        AllowlistText = string.Join(Environment.NewLine, _settings.AllowedIpCidrs);
        InstallFoldersText = string.Join(Environment.NewLine, _settings.ClaudeInstallDirectories);
        PathsText = string.Join(Environment.NewLine, _settings.ClaudeExecutablePaths);
        IntervalText = _settings.IpCheckIntervalSeconds.ToString();
        SettingsStrictMode = _settings.StrictMode;
        SettingsStartWithWindows = _settings.StartWithWindows;
        SettingsStartMinimized = _settings.StartMinimizedToTray;
        SettingsNotifications = _settings.ShowWindowsNotifications;
        SettingsBringToFront = _settings.BringAppToFrontOnDanger;
        StrictModeText = _settings.StrictMode ? "enabled" : "disabled";
    }

    private void RefreshLogsOnly()
    {
        var tail = _log.Tail(80);
        RecentLogs.Clear();
        foreach (var line in tail)
        {
            RecentLogs.Add(line);
        }
    }

    private void ShowToast(string message, ToastKind kind, bool autoDismiss = true)
    {
        void Apply()
        {
            ToastMessage = message;
            ToastBrush = kind switch
            {
                ToastKind.Success => "#238636",
                ToastKind.Warning => "#D29922",
                ToastKind.Error => "#DA3633",
                _ => "#0969DA"
            };
            ToastVisible = true;
            _toastTimer.Stop();
            if (autoDismiss)
            {
                _toastTimer.Start();
            }
        }

        var dispatcher = System.Windows.Application.Current.Dispatcher;
        if (dispatcher.CheckAccess())
        {
            Apply();
        }
        else
        {
            dispatcher.Invoke(Apply);
        }
    }

    private string DescribeCurrentState(string prefix)
    {
        if (_state is null)
        {
            return $"{prefix}: state is not ready yet.";
        }

        return _state.Decision.Status == SafetyStatus.Safe
            ? $"{prefix}: safe, Claude network allowed."
            : $"{prefix}: blocked. {_state.Decision.Reason}";
    }

    private ToastKind ToastKindForCurrentState()
    {
        if (_state?.Decision.Status == SafetyStatus.Safe)
        {
            return ToastKind.Success;
        }

        return _state?.Decision.Status == SafetyStatus.Danger ? ToastKind.Error : ToastKind.Warning;
    }

    private static IEnumerable<string> Lines(string text) =>
        (text ?? "").Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string FormatStatus(GuardRuntimeState state)
    {
        if (state.Decision.Status == SafetyStatus.Safe)
        {
            return "SAFE - Claude allowed";
        }

        if (state.Decision.Status == SafetyStatus.Danger)
        {
            return "DANGER - Claude blocked";
        }

        if (state.Firewall.RuleStatus is FirewallRuleStatus.Unknown or FirewallRuleStatus.Error)
        {
            return "BLOCKED - firewall needs attention";
        }

        if (!state.Ip.CheckSucceeded || state.Ip.PublicIp is null)
        {
            return "BLOCKED - waiting for IP verification";
        }

        return "BLOCKED - verification required";
    }

    private static string FormatStatusDetail(GuardRuntimeState state)
    {
        if (state.Decision.Status == SafetyStatus.Safe)
        {
            if (!string.IsNullOrWhiteSpace(state.Ip.Error))
            {
                return state.Ip.Error;
            }

            if (HasProviderIpRotation(state.Ip))
            {
                return $"Claude is allowed. Public IP is rotating inside {FormatCountry(state.Ip)}; a more stable VPN/server is recommended.";
            }

            if (HasDiagnosticSplitRoute(state.Ip))
            {
                return "Claude is allowed after authoritative IP checks. Diagnostic split-routing is visible in IP providers.";
            }

            return "Claude is allowed after a successful IP and firewall check.";
        }

        return $"Claude network access is blocked. Reason: {state.Decision.Reason}";
    }

    private static string FormatCountry(IpObservation ip)
    {
        if (!string.IsNullOrWhiteSpace(ip.CountryName) && !string.IsNullOrWhiteSpace(ip.CountryCode))
        {
            return $"{ip.CountryName} ({ip.CountryCode})";
        }

        return ip.CountryName ?? ip.CountryCode ?? "unknown";
    }

    private static string FormatLastDecision(GuardRuntimeState state)
    {
        var warning = state.Decision.Status == SafetyStatus.Safe && HasProviderIpRotation(state.Ip)
            ? $"Public IP is rotating inside {FormatCountry(state.Ip)}; a more stable VPN/server is recommended."
            : state.Ip.Error;
        return string.IsNullOrWhiteSpace(warning)
            ? state.Decision.Reason
            : $"{state.Decision.Reason} {warning}";
    }

    private static bool HasProviderIpRotation(IpObservation ip)
    {
        var comparer = new IpAddressComparer();
        return ip.PublicIp is not null
            && ip.ProviderReadings
                .Where(reading => reading.IsAuthoritative && reading.Address is not null)
                .Select(reading => reading.Address!)
                .Distinct(comparer)
                .Skip(1)
                .Any();
    }

    private static bool HasDiagnosticSplitRoute(IpObservation ip)
    {
        if (ip.PublicIp is null)
        {
            return false;
        }

        var comparer = new IpAddressComparer();
        return ip.ProviderReadings.Any(reading =>
            !reading.IsAuthoritative
            && reading.Address is not null
            && !comparer.Equals(reading.Address, ip.PublicIp));
    }

    private void Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public sealed class RelayCommand : ICommand
{
    private readonly Action _execute;

    public RelayCommand(Action execute) => _execute = execute;
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => true;
    public void Execute(object? parameter) => _execute();
}

public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private bool _running;

    public AsyncRelayCommand(Func<Task> execute) => _execute = execute;
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => true;

    public async void Execute(object? parameter)
    {
        if (_running)
        {
            return;
        }

        _running = true;
        try
        {
            await _execute();
        }
        finally
        {
            _running = false;
        }
    }
}

public enum ToastKind
{
    Info,
    Success,
    Warning,
    Error
}

public static class AppLogoPaths
{
    public static string Safe => Path.Combine(AppContext.BaseDirectory, "logos", "logog and safe state.png");
    public static string ConnectionBlocked => Path.Combine(AppContext.BaseDirectory, "logos", "connection blocked state.png");
    public static string ClaudeKilled => Path.Combine(AppContext.BaseDirectory, "logos", "claude killed.png");

    public static string ForState(GuardRuntimeState state) =>
        state.Decision.Status switch
        {
            SafetyStatus.Safe => Safe,
            SafetyStatus.Danger or SafetyStatus.Blocked => ClaudeKilled,
            _ => ConnectionBlocked
        };
}

public sealed record DangerWarning(string Title, string Message, bool ShowRecoveryActions, string LogoPath)
{
    public static DangerWarning UnsafeBlocked(string message) =>
        new("Unsafe IP detected. Claude network access has been blocked.", message, ShowRecoveryActions: true, AppLogoPaths.ClaudeKilled);

    public static DangerWarning ClaudeKilled(string message) =>
        new("Claude Desktop has already been killed.", message, ShowRecoveryActions: false, AppLogoPaths.ClaudeKilled);
}
