using Cta.IdentityServer.Models;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Cta.IdentityServer.Models.Extensions;

namespace Cta.IdentityServer.Services
{
    public class AppAuthorizeInteractionResponseGenerator : AuthorizeInteractionResponseGenerator
    {
        private readonly ISystemClock _systemClock;
        private IProfileService _profileService;
        //private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly UserManager _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AppAuthorizeInteractionResponseGenerator(
            UserManager userManager,
            SignInManager<ApplicationUser> signInManager,
            //IHttpContextAccessor httpContextAccessor,
            ISystemClock clock, 
            ILogger<AuthorizeInteractionResponseGenerator> logger, 
            IConsentService consent, 
            IProfileService profile
        )
            : base(clock, logger, consent, profile)
        {
            _systemClock = clock;
            _profileService = profile;
            //_httpContextAccessor = httpContextAccessor;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public override async Task<InteractionResponse> ProcessInteractionAsync(ValidatedAuthorizeRequest request, ConsentResponse consent = null)
        {
            var impersonateId = request.GetPrefixedAcrValue("impersonate:");
            var unimpersonateId = request.GetPrefixedAcrValue("unimpersonate:");
            if (impersonateId != null && request.Client?.ClientId == "toolbox")
            {
                var principal = request.Subject; //_httpContextAccessor.HttpContext.User;
                var currentUser = await _userManager.FindByNameAsync(principal.Identity.Name);
                var roles = await _userManager.GetRolesAsync(currentUser);
                var isAccountManager = roles.Any(x => x == "systemsettings_Account Management");
                var isDwAdmin = roles.Any(x => x == "Data Warehouse Administrator");
                var impersonatedUser = await _userManager.FindByIdAsync(impersonateId);
                if (impersonatedUser == null)
                    return await base.ProcessInteractionAsync(request, consent);
                var impersonatedUserTenantId = (await _userManager.GetRolesAsync(impersonatedUser))?.First(x => x.StartsWith("tenant"))?.Replace("tenant", "");
                var tenantMatches = principal?.HasClaim("tenant_id", impersonatedUserTenantId) ?? false;

                if ((isAccountManager && tenantMatches) || isDwAdmin)
                {

                    var origUsername = principal.GetOriginalUsername();
                    var origUserId = principal.GetOriginalUserId();
                    var origEmail = principal.GetOriginalEmail();

                    var newPrincipal = await _signInManager.CreateUserPrincipalAsync(impersonatedUser);
                    ((ClaimsIdentity) newPrincipal.Identity).AddClaims(
                        new[]
                        {
                            new Claim("impersonating", "true"),
                            new Claim("orig_user_id", origUserId),
                            new Claim("orig_username", origUsername),
                            new Claim("orig_email", origEmail)
                        }
                    );
                    foreach (var r in roles)
                    {
                        ((ClaimsIdentity)newPrincipal.Identity).AddClaim(new Claim("orig_role", r));
                    }
                    
                    await _signInManager.SignOutAsync();

                    await _signInManager.Context.SignInAsync(IdentityConstants.ApplicationScheme, newPrincipal, new AuthenticationProperties());
                    
                    /*
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
                    */
                }

            }
            else if (unimpersonateId != null) {

                var principal = request.Subject;
                if (principal.GetOriginalUserId() == unimpersonateId)
                {
                    var currentUser = await _userManager.FindByIdAsync(unimpersonateId);
                    await _signInManager.SignOutAsync();
                    await _signInManager.SignInAsync(currentUser, null);
                }
            }
            return await base.ProcessInteractionAsync(request, consent);
        }
    }
}
