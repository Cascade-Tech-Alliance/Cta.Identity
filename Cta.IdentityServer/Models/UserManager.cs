using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cta.IdentityServer.Models
{
    public class UserManager : UserManager<ApplicationUser>
    {
        public new IPasswordHasher<ApplicationUser> PasswordHasher { get; set; }
        public UserManager(
            IUserStore<ApplicationUser> store, 
            IOptions<IdentityOptions> optionsAccessor, 
            IPasswordHasher<ApplicationUser> passwordHasher, 
            IEnumerable<IUserValidator<ApplicationUser>> userValidators, 
            IEnumerable<IPasswordValidator<ApplicationUser>> passwordValidators, 
            ILookupNormalizer keyNormalizer, 
            IdentityErrorDescriber errors, 
            IServiceProvider services, 
            ILogger<UserManager<ApplicationUser>> logger
        )
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            PasswordHasher = new SqlPasswordHasher();
        }

    }
}
