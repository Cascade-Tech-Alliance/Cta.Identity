using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace Cta.IdentityServer.Models.Extensions
{
    public static class HttpContextAccessorExtensions
    {
        public static string CurrentUser(this HttpContextAccessor httpContextAccessor)
        {
            var userId = httpContextAccessor?.HttpContext?.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            return userId;
        }
    }
}
