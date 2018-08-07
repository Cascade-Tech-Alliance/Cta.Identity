using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Cta.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json;

namespace Cta.IdentityServer.Controllers
{
    [Authorize]
    public class UsersAdminController : Controller
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IUserClaimsPrincipalFactory<ApplicationUser> _principalFactory;
        public UsersAdminController (
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IUserClaimsPrincipalFactory<ApplicationUser> principalFactory
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _principalFactory = principalFactory;
        }

        //
        // GET: /Manage/GetUserAsync
        [HttpGet]
        public async Task<string> GetUserAsync(string id)
        {
            var user = await GetCurrentUserAsync();
            var userClaims = await _userManager.GetClaimsAsync(user);
            var targetUser = await _userManager.FindByIdAsync(id);
            var targetClaims = await _userManager.GetClaimsAsync(targetUser);
            var tenantId = targetClaims.First(x => x.Type.StartsWith("tenant")).Value.Replace("tenant", "");
            if (tenantId.Length > 0 && userClaims.Any(x => x.Type == "tenant_id" && x.Value == tenantId))
            {
                var targetPrincipal = (await _principalFactory.CreateAsync(targetUser)) as ClaimsPrincipal;
                return JsonConvert.SerializeObject(targetPrincipal);
            }
            return null;
        }

        ////[Authorize(Roles = "systemsettings_Account Management,Data Warehouse Administrator")]
        //public async Task ImpersonateUserAsync(string username, string originalUri) {
        //    var origUser = await GetCurrentUserAsync();
        //    var origUsername = origUser.UserName;
        //    var origUserId = origUser.Id;
        //    var origEmail = origUser.Email;
        //    var impersonatedUser = await _userManager.FindByNameAsync(username);
        //    if (impersonatedUser == null)
        //        return;
        //    var impersonatedIdentity = await _userManager.GetClaimsAsync(impersonatedUser);
        //    impersonatedIdentity.Add(new Claim("impersonating", "true"));
        //    impersonatedIdentity.Add(new Claim("orig_user_id", origUserId));
        //    impersonatedIdentity.Add(new Claim("orig_username", origUsername));
        //    impersonatedIdentity.Add(new Claim("orig_email", origEmail));
        //    impersonatedIdentity.Add(new Claim("orig_uri", originalUri));
        //    foreach(Claim c in HttpContext.User.Claims.Where(x => x.Type == "ods_role")){
        //        impersonatedIdentity.Add(new Claim("orig_ods_role", c.Value));
        //    }
        //    await HttpContext.SignOutAsync();
        //    await HttpContext.SignInAsync((await _principalFactory.CreateAsync(impersonatedUser)));
        //}

        ////[Authorize(Roles = "systemsettings_Account Management,Data Warehouse Administrator")]
        //public async Task RevertImpersonationAsync()
        //{
        //    if (!HttpContext.User.HasClaim("impersonating","true"))
        //    {
        //        throw new Exception("Unable to remove impersonation because there is no impersonation");
        //    }
        //    var currentUser = await GetCurrentUserAsync();
        //    var claims = await _userManager.GetClaimsAsync(currentUser);
        //    var originalUsernameClaim = claims.SingleOrDefault(c => c.Type == "orig_username");
        //    var originalUsername = originalUsernameClaim == null ? string.Empty : originalUsernameClaim.Value;
        //    await HttpContext.SignOutAsync();
        //    if (originalUsername.Length == 0)
        //        return;
        //    var originalUser = await _userManager.FindByNameAsync(originalUsername);
        //    //var originalIdentity = await _userManager.GetClaimsAsync(originalUser);
        //    await HttpContext.SignInAsync((await _principalFactory.CreateAsync(originalUser)));
        //}




        [HttpPost]
        public async Task<JsonResult> UpdateUserAsync(string id, string username = null, string email = null, string phone = null)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
                return Json(new { success = false, message = "A user with that Id does not exist." });

            if (username != null && user.UserName != username)
            {
                var otherUser = await _userManager.FindByNameAsync(username);
                if (otherUser != null)
                {
                    return Json(new { success = false, message = "An account with that username already exists." });
                }
                user.UserName = username;
            }
            if (email != null && user.Email != email)
            {
                user.Email = email;
            }
            if (phone != null)
            {
                user.PhoneNumber = phone;
            }

            var result = await _userManager.UpdateAsync(user);

            return Json(new { success = result.Succeeded });
        }


        private Task<ApplicationUser> GetCurrentUserAsync()
        {
            return _userManager.GetUserAsync(HttpContext.User);
        }
    }
}
