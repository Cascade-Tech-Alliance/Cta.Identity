using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Services;

namespace Cta.IdentityServer.Services
{
    public class AppProfileService : IProfileService
    {
        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            
            //assigning issuedclaims causes those claims to be passed to the client.
            //for now, we're simply saying that any claim associated with the user should go to the client application.
            //as other applications begin using our identityServer implementation, this won't be good enough.
            //todo: should we be trusting that the correct claims have been associated with the subject?
            context.IssuedClaims = context.Subject.Claims.ToList();

            return Task.FromResult(0);
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.FromResult(0);
        }
    }
}
