using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace Cta.IdentityServer.Models
{
    public class ApplicationUser : IdentityUser
    {
        ///// <summary>
        ///// Navigation property for the roles this user belongs to.
        ///// </summary>
        //public virtual ICollection<IdentityUserRole<int>> Roles { get; } = new List<IdentityUserRole<int>>();

        ///// <summary>
        ///// Navigation property for the claims this user possesses.
        ///// </summary>
        //public virtual ICollection<IdentityUserClaim<int>> Claims { get; } = new List<IdentityUserClaim<int>>();

        ///// <summary>
        ///// Navigation property for this users login accounts.
        ///// </summary>
        //public virtual ICollection<IdentityUserLogin<int>> Logins { get; } = new List<IdentityUserLogin<int>>();
    }
}
