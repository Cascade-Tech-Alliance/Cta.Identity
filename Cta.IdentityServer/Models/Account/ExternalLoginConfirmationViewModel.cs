using System.ComponentModel.DataAnnotations;

namespace Cta.IdentityServer.Models.Account
{
    public class ExternalLoginConfirmationViewModel
    {
        //[Required]
        //public string Username { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
