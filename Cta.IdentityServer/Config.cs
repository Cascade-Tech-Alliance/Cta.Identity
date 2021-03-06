﻿using IdentityModel;
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
                    ClientName = "Oregon Data Suite",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "oregon_data_suite"
                    },
                    RequireConsent = false,
                    RedirectUris = {
                        "https://toolbox.wesd.org",
                        "https://toolboxtest.wesd.org",
                        "https://toolboxdev.wesd.org",
                        "http://localhost:6506",
                        //sometimes we want to unimpersonate, and be redirected back to the account of the user who we were impersonating, so..
                        "https://toolbox.wesd.org/wf/systemsettings/accountmanagement.aspx",
                        "https://toolboxtest.wesd.org/wf/systemsettings/accountmanagement.aspx",
                        "https://toolboxdev.wesd.org/wf/systemsettings/accountmanagement.aspx",
                        "http://localhost:6506/wf/systemsettings/accountmanagement.aspx"
                    },
                    PostLogoutRedirectUris = {
                        "https://toolbox.wesd.org",
                        "https://toolboxtest.wesd.org",
                        "https://toolboxdev.wesd.org",
                        "http://localhost:6506"
                    },
                    AllowAccessTokensViaBrowser = true,
                    FrontChannelLogoutUri = "https://toolbox.wesd.org/signedout.aspx",
                    AllowedCorsOrigins =
                    {
                        "http://localhost:6506"
                    }
                    //,Properties = {
                    //    { "app_support_email","app.support@wesd.org" },
                    //    { "app_support_email_host", "mailhost.wesd.org" },
                    //    { "app_support_email_port", "25" },
                    //    { "app_support_email_enablessl", "false" }
                    //}
                },
                new Client
                {
                    ClientId = "dwnorth",
                    ClientName = "Oregon Data Suite",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "oregon_data_suite"
                    },
                    RequireConsent = false,
                    RedirectUris = {
                        "https://dwnorth.cascadetech.org",
                        "https://dwnorthtest.cascadetech.org",
                        "http://localhost:6506",
                        //sometimes we want to unimpersonate, and be redirected back to the account of the user who we were impersonating, so..
                        "https://dwnorth.cascadetech.org/wf/systemsettings/accountmanagement.aspx",
                        "https://dwnorthtest.cascadetech.org/wf/systemsettings/accountmanagement.aspx",
                        "http://localhost:6506/wf/systemsettings/accountmanagement.aspx"
                    },
                    PostLogoutRedirectUris = {
                        "https://dwnorth.cascadetech.org",
                        "https://dwnorthtest.cascadetech.org",
                        "http://localhost:6506"
                    },
                    AllowAccessTokensViaBrowser = true,
                    FrontChannelLogoutUri = "https://dwnorth.cascadetech.org/signedout.aspx"
                    //,Properties = {
                    //    { "app_support_email","dwnorth@cascadetech.org" },
                    //    { "app_support_email_host", "smtp.gmail.com" },
                    //    { "app_support_email_port", "587" },
                    //    { "app_support_email_enablessl", "true" }
                    //}
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

            //return new Dictionary<string, string>{
            //    { "app_support_email","dwnorth@cascadetech.org" },
            //    { "app_support_email_host", "smtp.nwresd.k12.or.us" },
            //    { "app_support_email_port", "25" },
            //    { "app_support_email_enablessl", "true" }
            //};
        }
    }
}
