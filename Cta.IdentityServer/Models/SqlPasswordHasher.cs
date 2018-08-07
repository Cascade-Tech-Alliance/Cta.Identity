using System;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace Cta.IdentityServer.Models
{
    public class SqlPasswordHasher : PasswordHasher<ApplicationUser>, IPasswordHasher<ApplicationUser>
    {

        public new string HashPassword(ApplicationUser user, string password)
        {
            return base.HashPassword(user, password);
        }

        public override PasswordVerificationResult VerifyHashedPassword(ApplicationUser user, string hashedPassword,
            string providedPassword)
        {
            string[] passwordProperties = hashedPassword.Split('|');
            if (passwordProperties.Length != 3)
            {
                return base.VerifyHashedPassword(user, hashedPassword, providedPassword);
            }
            var passwordHash = passwordProperties[0];
            var passwordformat = 1;
            var salt = passwordProperties[2];
            if (string.Equals(EncryptPassword(providedPassword, passwordformat, salt), passwordHash,
                StringComparison.CurrentCultureIgnoreCase))
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }
            return PasswordVerificationResult.Failed;
        }

        //This is copied from the existing SQL providers and is provided only for back-compat.
        private string EncryptPassword(string pass, int passwordFormat, string salt)
        {
            if (passwordFormat == 0) // MembershipPasswordFormat.Clear
                return pass;

            byte[] bIn = Encoding.Unicode.GetBytes(pass);
            byte[] bSalt = Convert.FromBase64String(salt);
            byte[] bRet = null;

            if (passwordFormat == 1)
            {
                // MembershipPasswordFormat.Hashed 

                var hm = SHA1.Create();
                var bAll = new byte[bSalt.Length + bIn.Length];
                Buffer.BlockCopy(bSalt, 0, bAll, 0, bSalt.Length);
                Buffer.BlockCopy(bIn, 0, bAll, bSalt.Length, bIn.Length);
                bRet = hm.ComputeHash(bAll);
            }

            return Convert.ToBase64String(bRet);

        }
    }
}
