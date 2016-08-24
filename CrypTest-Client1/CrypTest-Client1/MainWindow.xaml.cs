using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
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

namespace CrypTest_Client1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private SecClient1 _secClient1;
        private Logger _logger;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
            Closed += MainWindow_Closed;
            CloseButton.Click += CloseButton_Click;
            SendTestRequestButton.Click += SendTestRequestButton_Click;
            SendSecRequestButton.Click += SendSecRequestButton_Click;
            OpenClient2Button.Click += OpenClient2Button_Click;
        }

        private void SendSecRequestButton_Click(object sender, RoutedEventArgs e)
        {
            _logger.Write("Sending secure request to client 2...", isNewSection: true);
            string messageToSend = "Hello, this is a secure test message from client 1 to client 2.";
            _logger.Write("Message to send:");
            _logger.Write(messageToSend);
            var res = _secClient1.SendSecureRequest(messageToSend);
            _logger.Write("Response was: " + res);
        }

        private void OpenClient2Button_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(@"..\..\..\CryptTest-Client2\bin\Debug\CryptTest-Client2.exe");
        }

        private void SendTestRequestButton_Click(object sender, RoutedEventArgs e)
        {
            _logger.Write("Sending test request to client 2...");
            var res = _secClient1.SendRequest();
            _logger.Write("Response was: " + res);
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
            _secClient1 = new SecClient1(_logger);

            _logger.Write("Starting to listen for requests.");
            _secClient1.Start();
        }

        private void MainWindow_Closed(object sender, EventArgs e)
        {
            _secClient1.Dispose();
        }
    }

    public class Logger
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
