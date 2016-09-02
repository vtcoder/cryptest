using CryptTest_Lib.Logging;
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
            SendSecRequestButton.Click += SendSecRequestButton_Click;
            OpenClient1Button.Click += OpenClient1Button_Click;
        }

        private void SendSecRequestButton_Click(object sender, RoutedEventArgs e)
        {
            _logger.Write("Sending secure request to client 1...", isNewSection: true);
            string messageToSend = "Hello, this is a secure test message from client 2 to client 1.";
            _logger.Write("Message to send:");
            _logger.Write(messageToSend);
            var res = _secClient2.SendSecureRequest(messageToSend);
            _logger.Write("Response was: " + res);
        }

        private void OpenClient1Button_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(@"..\..\..\CrypTest-Client1\bin\Debug\CrypTest-Client1.exe");
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _logger = new Logger(this.LogTextBlock, this.LogScrollViewer);
            _logger.Write("Logger initialized.", false);

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

    public class Logger : ILogger
    {
        private TextBlock _logTextBlock;
        private ScrollViewer _logScrollViewer;

        public Logger(TextBlock logTextBlock, ScrollViewer logScrollViewer)
        {
            _logTextBlock = logTextBlock;
            _logScrollViewer = logScrollViewer;
        }

        public void Write(string message, bool addStartingNewLine = true, bool isNewSection = false)
        {
            _logTextBlock.Text +=
                (addStartingNewLine ? Environment.NewLine : "") +
                (isNewSection ? Environment.NewLine : "") +
                message;
            _logScrollViewer.ScrollToBottom();
        }
    }
}
