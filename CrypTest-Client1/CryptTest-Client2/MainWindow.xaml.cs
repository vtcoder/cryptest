using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace CryptTest_Client2
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private SecClient2 _secClient2;
        private Logger _logger;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
            Closed += MainWindow_Closed;
            CloseButton.Click += CloseButton_Click;
            SendTestRequestButton.Click += SendTestRequestButton_Click;
            OpenClient1Button.Click += OpenClient1Button_Click;
        }

        private void OpenClient1Button_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(@"..\..\..\CrypTest-Client1\bin\Debug\CrypTest-Client1.exe");
        }

        private void SendTestRequestButton_Click(object sender, RoutedEventArgs e)
        {
            _logger.Write("Sending test request to client 1...");
            var res = _secClient2.SendRequest();
            _logger.Write("Response was: " + res);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _logger = new Logger(this.LogTextBlock);
            _logger.Write("Logger initialized.");

            _logger.Write("Creating security client.");
            _secClient2 = new SecClient2(_logger);

            _logger.Write("Starting to listen for requests.");
            _secClient2.Start();
        }

        private void MainWindow_Closed(object sender, EventArgs e)
        {
            _secClient2.Dispose();
        }
    }

    public class Logger
    {
        private TextBlock _logTextBlock;

        public Logger(TextBlock logTextBlock)
        {
            _logTextBlock = logTextBlock;
        }

        public void Write(string message)
        {
            _logTextBlock.Text += message + Environment.NewLine;
        }
    }
}
