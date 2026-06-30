using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using WpfBrushes = System.Windows.Media.Brushes;
using WpfColor = System.Windows.Media.Color;

namespace ClaudeIPGuard.App;

public partial class MainWindow : Window
{
    private readonly bool _startMinimized;
    private readonly MainViewModel _viewModel;

    public MainWindow(bool startMinimized)
    {
        InitializeComponent();
        Icon = LoadImage(AppLogoPaths.Safe);
        _startMinimized = startMinimized;
        _viewModel = new MainViewModel(BringToFront, ShowDangerDialog, () => Tabs.SelectedIndex = 1);
        DataContext = _viewModel;
        Loaded += OnLoaded;
        Closed += (_, _) => _viewModel.Dispose();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await _viewModel.StartAsync();
        if (_startMinimized)
        {
            WindowState = WindowState.Minimized;
            Hide();
        }
    }

    public void BringToFront()
    {
        Show();
        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    private void ShowDangerDialog(DangerWarning warning)
    {
        BringToFront();

        var dialog = new Window
        {
            Title = "Claude IP Guard warning",
            Owner = this,
            Width = 620,
            Height = 330,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Topmost = true,
            ResizeMode = ResizeMode.NoResize,
            Background = WpfBrushes.White
        };

        var root = new Grid { Margin = new Thickness(20) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var title = new TextBlock
        {
            Text = warning.Title,
            FontWeight = FontWeights.Bold,
            FontSize = 20,
            Foreground = new System.Windows.Media.SolidColorBrush(WpfColor.FromRgb(218, 54, 51)),
            TextWrapping = TextWrapping.Wrap
        };
        root.Children.Add(title);

        var bodyPanel = new Grid { Margin = new Thickness(0, 18, 0, 0) };
        bodyPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        bodyPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var logo = LoadImage(warning.LogoPath);
        if (logo is not null)
        {
            var image = new System.Windows.Controls.Image
            {
                Source = logo,
                Width = 96,
                Height = 96,
                Stretch = System.Windows.Media.Stretch.Uniform,
                Margin = new Thickness(0, 0, 18, 0)
            };
            bodyPanel.Children.Add(image);
        }

        var body = new TextBlock
        {
            Text = warning.Message,
            FontSize = 14,
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap
        };
        Grid.SetColumn(body, 1);
        bodyPanel.Children.Add(body);

        Grid.SetRow(bodyPanel, 1);
        root.Children.Add(bodyPanel);

        var buttons = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, HorizontalAlignment = System.Windows.HorizontalAlignment.Right };
        AddDialogButton(buttons, "OK", () => dialog.Close());
        if (warning.ShowRecoveryActions)
        {
            AddDialogButton(buttons, "Kill Claude", () =>
            {
                _viewModel.KillClaudeCommand.Execute(null);
                dialog.Close();
            });
            AddDialogButton(buttons, "Open Logs", () =>
            {
                _viewModel.OpenLogsCommand.Execute(null);
                dialog.Close();
            });
            AddDialogButton(buttons, "Check Again", () =>
            {
                _viewModel.CheckNowCommand.Execute(null);
                dialog.Close();
            });
        }
        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        dialog.Content = root;
        dialog.Show();
    }

    private static void AddDialogButton(System.Windows.Controls.Panel panel, string text, Action action)
    {
        var button = new System.Windows.Controls.Button { Content = text, MinWidth = 96, Cursor = System.Windows.Input.Cursors.Hand };
        button.Click += (_, _) => action();
        panel.Children.Add(button);
    }

    private static BitmapImage? LoadImage(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.UriSource = new Uri(path, UriKind.Absolute);
        image.EndInit();
        image.Freeze();
        return image;
    }
}
