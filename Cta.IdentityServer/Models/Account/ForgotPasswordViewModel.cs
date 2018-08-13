using System.ComponentModel.DataAnnotations;

namespace Cta.IdentityServer.Models.Account
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
