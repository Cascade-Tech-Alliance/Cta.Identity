using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace Cta.IdentityServer.Models.Extensions
{
    public static class PrincipalExtensions
    {
        public static string GetUserId(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            return claimsPrincipal?.FindFirst("sub")?.Value;
        }

        public static bool IsImpersonating(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            return claimsPrincipal != null && claimsPrincipal.HasClaim("impersonating", "true");
        }

        public static List<string> GetRoles(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            var l = new List<string>();
            if (claimsPrincipal == null) return l;
            foreach (var c in claimsPrincipal.Claims.Where(x => x.Type == "ods_role"))
            {
                l.Add(c.Value);
            }
            return l;
        }
        public static string GetFirstName(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            return claimsPrincipal?.FindFirst("given_name")?.Value;
        }

        public static string GetLastName(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            return claimsPrincipal?.FindFirst("family_name")?.Value;
        }
        public static string GetPhone(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            return claimsPrincipal?.FindFirst("phone")?.Value;
        }
        public static string GetEmail(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            return claimsPrincipal?.FindFirst("email")?.Value;
        }
        public static List<string> GetTenantIds(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            var l = new List<string>();
            if (claimsPrincipal == null) return l;
            foreach (var c in claimsPrincipal.Claims.Where(x => x.Type.EndsWith("ods_tenant_id")))
            {
                l.Add(c.Value);
            }
            return l;
        }


        //public static string GetEmployeeNumber(this ClaimsPrincipal claimsPrincipal)
        //{
        //    return claimsPrincipal.FindFirstValue("EmployeeNumber");
        //}

        /// <summary>
        /// Get a boolean indicating whether the user is in the specified role. If impersonating, this is the original user, not the impersonated user. 
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public static bool IsOriginalUserInRole(this IPrincipal principal, string roleName)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            if (!claimsPrincipal.IsImpersonating())
                return claimsPrincipal != null && claimsPrincipal.IsInRole(roleName);
            return claimsPrincipal != null && claimsPrincipal.HasClaim("orig_ods_role", roleName);
        }

        /// <summary>
        /// Get the userId of the logged in user. If impersonating, this is the original user, not the impersonated user. 
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public static string GetOriginalUserId(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            if (claimsPrincipal == null)
            {
                return null;
            }
            if (!claimsPrincipal.IsImpersonating())
            {
                return claimsPrincipal.GetUserId();
            }
            var originalUserIdClaim = claimsPrincipal.Claims.SingleOrDefault(c => c.Type == "orig_user_id");
            return originalUserIdClaim == null ? string.Empty : originalUserIdClaim.Value;
        }

        /// <summary>
        /// Get the username of the logged in user. If impersonating, this is the original user, not the impersonated user. 
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public static string GetOriginalUsername(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            if (claimsPrincipal == null)
            {
                return string.Empty;
            }

            if (!claimsPrincipal.IsImpersonating())
            {
                return claimsPrincipal.Identity.Name;
            }

            var originalUsernameClaim = claimsPrincipal.Claims.SingleOrDefault(c => c.Type == "orig_username");

            return originalUsernameClaim == null ? string.Empty : originalUsernameClaim.Value;
        }

        public static string GetOriginalUri(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            if (claimsPrincipal == null)
            {
                return string.Empty;
            }

            if (!claimsPrincipal.IsImpersonating())
            {
                return string.Empty;
            }
            var originalUriClaim = claimsPrincipal.Claims.SingleOrDefault(c => c.Type == "orig_uri");

            return originalUriClaim == null ? string.Empty : originalUriClaim.Value;
        }

        /// <summary>
        /// Get the email address of the logged in user. If impersonating, this is the original user, not the impersonated user. 
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public static string GetOriginalEmail(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            if (claimsPrincipal == null)
            {
                return string.Empty;
            }

            if (!claimsPrincipal.IsImpersonating())
            {
                return claimsPrincipal.GetEmail();
            }

            var originalEmailClaim = claimsPrincipal.Claims.SingleOrDefault(c => c.Type == "orig_email");

            return originalEmailClaim == null ? string.Empty : originalEmailClaim.Value;
        }
        //public static List<string> GetOriginalRoles(this IPrincipal principal)
        //{
        //    var claimsPrincipal = principal as ClaimsPrincipal;
        //    var l = new List<string>();
        //    if (claimsPrincipal != null)
        //    {
        //        foreach (var c in claimsPrincipal.Claims.Where(x => x.Type == "orig_ods_role"))
        //        {
        //            l.Add(c.Value);
        //        }
        //    }
        //    return l;
        //}
    }
}
