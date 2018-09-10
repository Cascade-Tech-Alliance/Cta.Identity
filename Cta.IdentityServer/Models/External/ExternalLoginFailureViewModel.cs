
namespace Cta.IdentityServer.Models.External
{
    public class ExternalLoginFailureViewModel
    {
        public string Email { get; set; }
        public string RedirectUri { get; set; }
        public string ClientName { get; set; }
        //public string Provider { get; set; }
    }
}
