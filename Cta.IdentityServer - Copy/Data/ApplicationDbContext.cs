using Cta.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Cta.IdentityServer.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            //builder.Entity<ApplicationUser>(i =>
            //{
            //    i.ToTable("Users");
            //    i.HasKey(x => x.Id);
            //});
            //builder.Entity<IdentityRole>(i =>
            //{
            //    i.ToTable("Roles");
            //    i.HasKey(x => x.Id);
            //});
            //builder.Entity<IdentityUserRole<int>>(i =>
            //{
            //    i.ToTable("UserRoles");
            //    i.HasKey(x => new { x.RoleId, x.UserId });
            //});
            //builder.Entity<IdentityUserLogin<int>>(i =>
            //{
            //    i.ToTable("UserLogins");
            //    i.HasKey(x => new { x.UserId, x.ProviderKey });
            //    i.HasIndex(x => new { x.ProviderKey, x.LoginProvider });
            //});
            //builder.Entity<IdentityRoleClaim<int>>(i =>
            //{
            //    i.ToTable("RoleClaims");
            //    i.HasKey(x => x.Id);
            //});
            //builder.Entity<IdentityUserClaim<int>>(i =>
            //{
            //    i.ToTable("UserClaims");
            //    i.HasKey(x => x.Id);
            //});
            //builder.Entity<IdentityUserToken<int>>(i => {
            //    i.ToTable("UserTokens");
            //    i.HasKey(x => x.UserId);
            //});

            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);

        }
    }
}
