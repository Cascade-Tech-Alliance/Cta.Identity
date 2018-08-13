using System.ComponentModel.DataAnnotations;

namespace Cta.IdentityServer.Models.AccountViewModels
{
    public class LoginViewModel
    {
        [Required]
        public string Username { get; set; }

        //[Required]
        //[EmailAddress]
        //public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
