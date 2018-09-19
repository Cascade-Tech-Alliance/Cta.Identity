using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;
using System.Security.Claims;

namespace Cta.IdentityServer
{
    public class Config
    {
        // scopes define the resources in your system
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                new IdentityResource {
                    Name = "oregon_data_suite",
                    DisplayName="User Role",
                    Description="The application can see your role.",
                    UserClaims = new[]{ JwtClaimTypes.Role, ClaimTypes.Role, "impersonating", "orig_user_id", "orig_username", "orig_email", "orig_role" },
                    ShowInDiscoveryDocument = true,
                    Required=true,
                    Emphasize = true
                }
                //,new IdentityResource
                //{
                //    Name = "impersonation",
                //    DisplayName = "Impersonation",
                //    Description = "The application can keep track of the impersonator.",
                //    UserClaims = new[]{ "impersonating", "orig_user_id", "orig_username", "orig_email", "orig_role"},
                //    Required=true,
                //    Emphasize = true
                //}
            };
        }

        

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
            };
                
        }

        // clients want to access resources (aka scopes)
        public static IEnumerable<Client> GetClients()
        {
            // client credentials client
            return new List<Client>
            {
                new Client
                {
                    ClientId = "toolbox",
                    ClientName = "Cascade Technology Alliance",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "oregon_data_suite"
                        //,"impersonation"
                    },
                    RequireConsent = false,
                    RedirectUris = {
                        "https://toolbox.wesd.org",
                        "https://toolboxtest.wesd.org",
                        "http://localhost:6506",
                        //sometimes we want to unimpersonate, and be redirected back to the account of the user who we were impersonating, so..
                        "https://toolbox.wesd.org/wf/systemsettings/accountmanagement.aspx",
                        "https://toolboxtest.wesd.org/wf/systemsettings/accountmanagement.aspx",
                        "http://localhost:6506/wf/systemsettings/accountmanagement.aspx"
                    },
                    PostLogoutRedirectUris = {
                        "https://toolbox.wesd.org",
                        "https://toolboxtest.wesd.org",
                        "http://localhost:6506"
                    },
                    AllowAccessTokensViaBrowser = true,
                    FrontChannelLogoutUri = "https://toolbox.wesd.org/signedout.aspx"
                }
            };
        }


        public static Dictionary<string, string> Items()
        {
            return new Dictionary<string, string>{
                { "app_support_email","app.support@wesd.org" },
                { "app_support_email_host", "mailhost.wesd.org" },
                { "app_support_email_port", "25" },
                { "app_support_email_enablessl", "false" }
            };
        }
    }
}
