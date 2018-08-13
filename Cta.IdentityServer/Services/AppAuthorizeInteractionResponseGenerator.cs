using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cta.IdentityServer.Services
{
    public class AppAuthorizeInteractionResponseGenerator : AuthorizeInteractionResponseGenerator
    {
        private readonly ISystemClock _systemClock;
        private IProfileService _profileService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly UserStore _userStore;

        public AppAuthorizeInteractionResponseGenerator(UserStore userStore, IHttpContextAccessor httpContextAccessor,
            ISystemClock clock, ILogger<AuthorizeInteractionResponseGenerator> logger, IConsentService consent, IProfileService profile)
            : base(clock, logger, consent, profile)
        {
            _systemClock = clock;
            _profileService = profile;
            _httpContextAccessor = httpContextAccessor;
            _userStore = userStore;
        }

        public override Task<InteractionResponse> ProcessInteractionAsync(ValidatedAuthorizeRequest request, ConsentResponse consent = null)
        {
            string impersonateId = request.GetPrefixedAcrValue("Impersonate:");
            if (request?.Client?.ClientId == "toolbox")
            {
                var currentUser = _httpContextAccessor.HttpContext.User;
                if (currentUser.IsInRole(""))
                    var impersonatedUser = _userStore.FindByIdAsync(impersonateId);

                var impersonatedUserTenantId = impersonatedUser

                if (impersonatedUser != null)
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

                    //Need this claim to flow through to client
                    context.IssuedClaims.Add(new Claim(Constants.ClaimTypes.Impersonation, currentUser.UserName));

                    foreach (Claim claim in context.IssuedClaims)
                    {
                        idSrvUser.AdditionalClaims.Add(claim);
                    }

                    ClaimsPrincipal newSubject = idSrvUser.CreatePrincipal();

                    request.Subject = newSubject;

                    Logger.LogInformation("Impersonation set, returning response");

                    return new InteractionResponse();
                }
                else
                {
                    Logger.LogWarning("Invalid attempt to impersonate user");
                    return new InteractionResponse { Error = "Invalid attempt to impersonate user" };
                }
            }
            return await base.ProcessInteractionAsync(request, consent);
        }
    }
}
