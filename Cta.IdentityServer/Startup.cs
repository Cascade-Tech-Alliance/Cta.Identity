using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Cta.IdentityServer.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Cta.IdentityServer.Models;
using Cta.IdentityServer.Services;
using Microsoft.AspNetCore.Http;
using IdentityServer4;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace Cta.IdentityServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
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

            
            services
                .AddIdentityServer()
                //.AddDeveloperSigningCredential()
                .AddSigningCredential(GetCert())
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
                .AddAspNetIdentity<ApplicationUser>()
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                .AddAuthorizeInteractionResponseGenerator<AppAuthorizeInteractionResponseGenerator>();

            services.AddAuthentication()
                .AddJwtBearer()
                .AddGoogle("Google", options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.ClientId = "777176799863-0qojj2c8ieltqmlf55jl20grlvgpq8ie.apps.googleusercontent.com";
                    options.ClientSecret = "E2_mhLzJh93JJQ2COZKCAwLr";
                });
        }


        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                //app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                //app.UseDeveloperExceptionPage();
                //app.UseDatabaseErrorPage();
                app.UseExceptionHandler("/Home/Error");
            }

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
