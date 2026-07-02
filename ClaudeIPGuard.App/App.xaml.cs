using WpfApplication = System.Windows.Application;
using WpfMessageBox = System.Windows.MessageBox;

namespace ClaudeIPGuard.App;

public partial class App : WpfApplication
{
    private Mutex? _singleInstanceMutex;
    private bool _ownsSingleInstanceMutex;

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        var startMinimized = e.Args.Contains("--minimized", StringComparer.OrdinalIgnoreCase);
        _singleInstanceMutex = new Mutex(initiallyOwned: true, "Local\\ClaudeIPGuard.SingleInstance", out var ownsMutex);
        _ownsSingleInstanceMutex = ownsMutex;
        if (!ownsMutex)
        {
            if (!startMinimized)
            {
                WpfMessageBox.Show(
                    "Claude IP Guard is already running. Use the tray icon to open it.",
                    "Claude IP Guard",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Information);
            }

            Shutdown();
            return;
        }

        base.OnStartup(e);
        var window = new MainWindow(startMinimized);
        window.Show();
    }

    protected override void OnExit(System.Windows.ExitEventArgs e)
    {
        if (_ownsSingleInstanceMutex)
        {
            _singleInstanceMutex?.ReleaseMutex();
        }

        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }
}
