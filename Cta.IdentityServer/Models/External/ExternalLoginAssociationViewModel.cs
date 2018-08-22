using System.ComponentModel.DataAnnotations;

namespace Cta.IdentityServer.Models.External
{
    public class ExternalLoginAssociationViewModel
    {
        //[Required]
        //public string Username { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }
        public string Provider { get; set; }
        public string ProviderDisplayName { get; set; }
        public string ProviderKey { get; set; }
        public string ReturnUrl { get; set; }
    }
}
