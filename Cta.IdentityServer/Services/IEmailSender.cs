using System.Threading.Tasks;

namespace Cta.IdentityServer.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }
}
