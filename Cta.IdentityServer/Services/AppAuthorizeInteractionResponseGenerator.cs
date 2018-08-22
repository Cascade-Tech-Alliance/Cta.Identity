using Cta.IdentityServer.Models;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Cta.IdentityServer.Services
{
    public class AppAuthorizeInteractionResponseGenerator : AuthorizeInteractionResponseGenerator
    {
        private readonly ISystemClock _systemClock;
        private IProfileService _profileService;
        //private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly UserManager _userManager;

        public AppAuthorizeInteractionResponseGenerator(
            UserManager userManager, 
            //IHttpContextAccessor httpContextAccessor,
            ISystemClock clock, ILogger<AuthorizeInteractionResponseGenerator> logger, IConsentService consent, IProfileService profile)
            : base(clock, logger, consent, profile)
        {
            _systemClock = clock;
            _profileService = profile;
            //_httpContextAccessor = httpContextAccessor;
            _userManager = userManager;
        }

        public override async Task<InteractionResponse> ProcessInteractionAsync(ValidatedAuthorizeRequest request, ConsentResponse consent = null)
        {
            var impersonateId = request.GetPrefixedAcrValue("impersonate:");
            var unimpersonateId = request.GetPrefixedAcrValue("unimpersonate:");
            if (impersonateId != null)
            {
                var principal = request.Subject; //_httpContextAccessor.HttpContext.User;
                var currentUser = await _userManager.FindByNameAsync(principal.Identity.Name);
                var roles = await _userManager.GetRolesAsync(currentUser);
                var isAccountManager = roles.Any(x => x == "systemsettings_Account Management"); //principal?.IsInRole("systemsettings_Account Management") ?? false;
                var isDWAdmin = roles.Any(x => x == "Data Warehouse Administrator"); //principal?.IsInRole("Data Warehouse Administrator") ?? false;
                var impersonatedUser = await _userManager.FindByIdAsync(impersonateId);
                var impersonatedUserTenantId = (await _userManager.GetRolesAsync(impersonatedUser))?.First(x => x.StartsWith("tenant"))?.Replace("tenant", "");
                var tenantMatches = principal?.HasClaim("tenant_id", impersonatedUserTenantId) ?? false;

                if (
                    request?.Client?.ClientId == "toolbox"
                    && principal != null
                    && impersonatedUser != null
                    && ((isAccountManager && tenantMatches) || isDWAdmin)
                )
                {
                    IEnumerable<string> requestedClaimTypes = request.Client.AllowedScopes;

                    IdentityServerUser idSrvUser = new IdentityServerUser(impersonatedUser.Id.ToString())
                    {
                        AuthenticationTime = Clock.UtcNow.UtcDateTime,
                        DisplayName = impersonatedUser.UserName,
                        IdentityProvider = !string.IsNullOrEmpty(impersonatedUser.PasswordHash) ? IdentityServerConstants.LocalIdentityProvider : "external"
                    };

                    ProfileDataRequestContext context = new ProfileDataRequestContext(
                        idSrvUser.CreatePrincipal(),
                        request.Client,
                        nameof(AuthorizeInteractionResponseGenerator),
                        requestedClaimTypes);

                    await Profile.GetProfileDataAsync(context);

                    //Need claims of impersonating user
                    var origUserId = currentUser.Id;
                    var origUserName = currentUser.UserName;
                    var origEmail = currentUser.Email;

                    idSrvUser.AdditionalClaims.Add(new Claim("impersonating", "true"));
                    //context.IssuedClaims.Add(new Claim("impersonating", "true"));
                    idSrvUser.AdditionalClaims.Add(new Claim("orig_user_id", origUserId));
                    //context.IssuedClaims.Add(new Claim("orig_user_id", origUserId));
                    idSrvUser.AdditionalClaims.Add(new Claim("orig_username", origUserName));
                    //context.IssuedClaims.Add(new Claim("orig_username", origUserName));
                    idSrvUser.AdditionalClaims.Add(new Claim("orig_email", origEmail));
                    //context.IssuedClaims.Add(new Claim("orig_email", origEmail));
                    //foreach (Claim c in principal.Claims.Where(x => x.Type == "ods_role"))
                    foreach(string r in roles)
                    {
                        idSrvUser.AdditionalClaims.Add(new Claim("orig_ods_role", r));
                        //context.IssuedClaims.Add(new Claim("orig_ods_role", c.Value));
                    }

                    //need claims of impersonated user
                    foreach (Claim claim in context.IssuedClaims)
                    {
                        idSrvUser.AdditionalClaims.Add(claim);
                    }

                    ClaimsPrincipal newSubject = idSrvUser.CreatePrincipal();

                    request.Subject = newSubject;

                    Logger.LogInformation("Impersonation set, returning response");

                    return new InteractionResponse();
                }

            }
            else if (unimpersonateId != null) {
                //todo: implement unimpersonate functionality
                return await base.ProcessInteractionAsync(request, consent);
            }
            return await base.ProcessInteractionAsync(request, consent);
        }
    }
}
