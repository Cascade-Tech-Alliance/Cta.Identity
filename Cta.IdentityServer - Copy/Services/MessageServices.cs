using System;
using System.Net.Mail;
using System.Threading.Tasks;

namespace Cta.IdentityServer.Services
{
    // This class is used by the application to send Email and SMS
    // when you turn on two-factor authentication in ASP.NET Identity.
    // For more details see this link http://go.microsoft.com/fwlink/?LinkID=532713
    public class AuthMessageSender : IEmailSender, ISmsSender
    {
        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var items = Config.Items();
            var sender = items["app_support_email"];
            using (var mailMessage = new MailMessage(sender, email, subject, message)) {

                mailMessage.IsBodyHtml = true;

                var host = items["app_support_email_host"];
                int port = Convert.ToInt32(items["app_support_email_port"]);
                using (var client = new SmtpClient(host,port))
                {
                    await client.SendMailAsync(mailMessage);
                }
            }
        }

        public Task SendSmsAsync(string number, string message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }
    }
}
