// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Cta.IdentityServer.Models;
//using IdentityServer4.Quickstart.UI;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using IdentityServer4.Stores;
using Microsoft.EntityFrameworkCore.SqlServer.Query.ExpressionTranslators.Internal;

namespace Cta.IdentityServer.Controllers
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IHostingEnvironment _environment;
        private readonly IClientStore _clientStore;

        public HomeController(IIdentityServerInteractionService interaction, IHostingEnvironment environment, IClientStore clientStore)
        {
            _interaction = interaction;
            _environment = environment;
            _clientStore = clientStore;
        }

        public IActionResult Index()
        {
            if (_environment.IsDevelopment())
            {
                // only show in development
                return View();
            }

            return NotFound();
        }

        /// <summary>
        /// Shows the error page
        /// </summary>
        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

           // retrieve error details from identityserver
            var message = await _interaction.GetErrorContextAsync(errorId);

            if (message != null)
            {
                vm.Error = message;

                if (!_environment.IsDevelopment())
                {
                    // only show in development
                    message.ErrorDescription = null;
                }
            }

            return View("Error", vm);
        }
    }
}