using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Cta.IdentityServer.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Cta.IdentityServer.Models;
using Cta.IdentityServer.Services;
using Microsoft.AspNetCore.Http;
using IdentityServer4;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Linq;
using IdentityServer4.Configuration;
using IdentityServer4.Services;
using Cta.IdentityServer.Models.Account;

namespace Cta.IdentityServer
{
    public class Startup
    {
        private ILogger<DefaultCorsPolicyService> _logger;
        public Startup(IConfiguration configuration, ILoggerFactory loggerFactory)
        {
            Configuration = configuration;
            //loggerFactory.AddConsole(LogLevel.Trace);
            _logger = loggerFactory.CreateLogger<DefaultCorsPolicyService>();
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) //, ILoggerFactory loggerFactory)
        {
            services.AddCors();

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("Identity")));

            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddIdentity<ApplicationUser, IdentityRole>(x =>
            {
                x.Password.RequireDigit = false;
                x.Password.RequiredLength = 7;
                x.Password.RequireNonAlphanumeric = false;
                x.Password.RequireUppercase = false;
                x.Password.RequireLowercase = false;
                x.Lockout.MaxFailedAccessAttempts = 5;
            })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddUserManager<UserManager>()
                .AddDefaultTokenProviders();

            // Add application services.
            services.AddMvc();

            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
            //services.AddSingleton(Configuration);
            services.AddSingleton<IPasswordHasher<ApplicationUser>, SqlPasswordHasher>();

            services
                .AddIdentityServer(options => { options.Authentication.CookieLifetime = AccountOptions.LoginDuration; })
                //.AddDeveloperSigningCredential()
                .AddSigningCredential(GetCert())
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
                .AddAspNetIdentity<ApplicationUser>()
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                .AddAuthorizeInteractionResponseGenerator<AppAuthorizeInteractionResponseGenerator>();

            services.AddAuthentication()
                //.AddGoogle("Google", options =>
                //{
                //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                //    options.ClientId = "777176799863-0qojj2c8ieltqmlf55jl20grlvgpq8ie.apps.googleusercontent.com";
                //    options.ClientSecret = "E2_mhLzJh93JJQ2COZKCAwLr";
                //});
                .AddGoogle("Google", options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.ClientId = "763788758047-0m9oq2kpdi1c1rfpcdrlj29aa2pdseur.apps.googleusercontent.com";
                    options.ClientSecret = "xiM0HK861ero67mJusSjEy3O";
                });

            services.AddTransient<IProfileService, AppProfileService>();
        }


        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseCors("default");

            app.UseStaticFiles();

            // app.UseAuthentication(); // not needed, since UseIdentityServer adds the authentication middleware
            app.UseIdentityServer();
            
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        public X509Certificate2 GetCert()
        {
            var p = Directory.GetCurrentDirectory();
            var certFileName = Path.Combine(p, "idp.wesd.org.pfx");
            if (!File.Exists(certFileName))
            {
                throw new FileNotFoundException("Signing Certificate is missing!");
            }
            var cert = new X509Certificate2(certFileName, "2611Pringle");
            return cert;
        }
    }
}
