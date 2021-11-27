using Microsoft.Maui.Controls;
using Microsoft.Maui.Essentials;
using System;

namespace Settings
{
    public partial class MainPage : NavigationPage
    {
        public MainPage()
        {
            InitializeComponent();
        }

        private void Connect(object sender, EventArgs e)
        {

        }
        private void FIPS_Settings(object sender, EventArgs e)
        {

        }

        private void Home_Settings(object sender, EventArgs e)
        {
            Console.WriteLine("FIPS Settings Entered");
        }

        private void Auth_Settings(object sender, EventArgs e)
        {

        }

        private void Server_Settings(object sender, EventArgs e)
        {

        }

        private void Data_Settings(object sender, EventArgs e)
        {

        }
    }
}
