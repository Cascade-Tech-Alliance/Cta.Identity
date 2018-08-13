using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cta.IdentityServer.Models.AccountViewModels
{
    public class LogoutViewModel : LogoutInputModel
    {
        public bool ShowLogoutPrompt { get; set; } = true;
    }
}
