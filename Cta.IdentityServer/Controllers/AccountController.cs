using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Cta.IdentityServer.Models;
using Cta.IdentityServer.Models.AccountViewModels;
using Cta.IdentityServer.Services;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;

namespace Cta.IdentityServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ISmsSender _smsSender;
        private readonly ILogger _logger;
        public AccountController(
            UserManager userManager,
            IUserStore<ApplicationUser> userStore,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILoggerFactory loggerFactory
        )
        {
            _userManager = userManager;
            _userStore = userStore;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _logger = loggerFactory.CreateLogger<AccountController>();
        }
        //
        // GET: /Account/Login
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                ApplicationUser user = await GetUserByUsernameOrEmail(model.Username);
                if (user == null)
                {
                    _logger.LogWarning(2, "User account does not exist.");
                    return View("Lockout");
                }

                var isLockedOut = await _userManager.IsLockedOutAsync(user);
                if (isLockedOut)
                {
                    _logger.LogWarning(2, "User account is locked.");
                    return View("Lockout");
                }

                var result = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password);

                if (result != PasswordVerificationResult.Failed) //result is either Success or SuccessRehashNeeded
                {
                    if (result == PasswordVerificationResult.SuccessRehashNeeded)
                    {
                        //update passwordHash from old to new encryption
                        user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, model.Password);
                    }
                    user.AccessFailedCount = 0;
                    user.LockoutEnd = null;
                    await _userManager.UpdateAsync(user);
                    //await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, false);
                    await _signInManager.SignInAsync(user, model.RememberMe);
                    _logger.LogInformation(1, "User logged in.");
                    //return RedirectToLocal(returnUrl);
                    Response.Redirect(returnUrl ?? "~/Account/"); //RedirectToLocal(returnUrl);
                }

                //result is Failed
                user.AccessFailedCount++;
                if (user.AccessFailedCount >= 6)
                {
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(15);
                    await _userManager.UpdateAsync(user);
                    _logger.LogWarning(2, "User account locked out.");
                    return View("Lockout");
                }
                await _userManager.UpdateAsync(user);

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);

            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        public async Task<ApplicationUser> GetUserByUsernameOrEmail(string username) {
            ApplicationUser user = await _userManager.FindByNameAsync(username);
            if (user == null) {
                if (IsValidEmail(username)) {
                    user = await _userManager.FindByEmailAsync(username);
                }
            }
            return user;
        }

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        // GET: /Account/ConfirmEmail
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return View("Error");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }


        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        //
        // GET: /Account/ExternalLoginCallback
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View(nameof(Login));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
            {
                _logger.LogInformation(5, "User logged in with {Name} provider.", info.LoginProvider);
                Response.Redirect(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl });
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["LoginProvider"] = info.LoginProvider;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                /*
                    Currently, we either manually create accounts or we create them via a build process.  We don't allow users to create their 
                    own account through registration. However, we do allow them to associate their Google login credentials with their existing  
                    account. So I've commented out the part where we're creating new accounts here, and added similar code to simply find the 
                    user, based on the email address entered, and associate the external login with the user. -Travis 7-13-2018
                */

                //var user = new ApplicationUser { UserName = info.Principal.GetName(), Email = model.Email };
                //var result = await _userManager.CreateAsync(user);
                //if (result.Succeeded)
                //{
                //    result = await _userManager.AddLoginAsync(user, info);
                //    if (result.Succeeded)
                //    {
                //        await _signInManager.SignInAsync(user, isPersistent: false);
                //        _logger.LogInformation(6, "User created an account using {Name} provider.", info.LoginProvider);
                //        Response.Redirect(returnUrl);
                //    }
                //}
                //AddErrors(result);

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    _logger.LogWarning(2, "User account not found after external authentication.");
                    return View("ExternalLoginAssociationFailure");
                }
                var result = await _userManager.AddLoginAsync(user, info);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation(6, "User associated {Name} provider, with their account.", info.LoginProvider);
                    Response.Redirect(returnUrl);
                }
                AddErrors(result);
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View(model);
        }

        //
        // GET: /Account/ForgotPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                /*
                Originally, password recovery couldn't happen if the user's email had not been confirmed, but the password recovery 
                process is so much like the email confirmation process, in that the user has to have access to the email in which 
                the link is embedded, and clicking on the link tells us that the user has that access, so I kind of didn't see the 
                point in requiring email confirmation for password recovery.  I may be missing something, but I commented it out here. 
                -Travis 7/11/2018
                */
                if (user == null) // || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
                // Send an email with this link
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
                await _emailSender.SendEmailAsync(model.Email, "Reset Password", $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");

                return View("ForgotPasswordConfirmation");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }



        //
        // GET: /Account/ResetPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }


        //
        // GET: /Account/SendCode
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            var userFactors = await _userManager.GetValidTwoFactorProvidersAsync(user);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }

            // Generate the token and send it
            var code = await _userManager.GenerateTwoFactorTokenAsync(user, model.SelectedProvider);
            if (string.IsNullOrWhiteSpace(code))
            {
                return View("Error");
            }

            var message = "Your security code is: " + code;
            if (model.SelectedProvider == "Email")
            {
                await _emailSender.SendEmailAsync(await _userManager.GetEmailAsync(user), "Security Code", message);
            }
            else if (model.SelectedProvider == "Phone")
            {
                await _smsSender.SendSmsAsync(await _userManager.GetPhoneNumberAsync(user), message);
            }

            return RedirectToAction(nameof(VerifyCode), new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/VerifyCode
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyCode(string provider, bool rememberMe, string returnUrl = null)
        {
            // Require that the user has already logged in via username/password or external login
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes.
            // If a user enters incorrect codes for a specified amount of time then the user account
            // will be locked out for a specified amount of time.
            var result = await _signInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe, model.RememberBrowser);
            if (result.Succeeded)
            {
                Response.Redirect(model.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning(7, "User account locked out.");
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid code.");
                return View(model);
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}