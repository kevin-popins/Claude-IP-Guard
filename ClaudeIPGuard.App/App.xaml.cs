using WpfApplication = System.Windows.Application;

namespace ClaudeIPGuard.App;

public partial class App : WpfApplication
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);
        var window = new MainWindow(e.Args.Contains("--minimized", StringComparer.OrdinalIgnoreCase));
        window.Show();
    }
}
