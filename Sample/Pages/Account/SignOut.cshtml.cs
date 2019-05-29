using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.V3.Pages.Account.Internal;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace TheMyAsk.Web.Pages.Account
{
    [AllowAnonymous]
    public class SignOut : PageModel
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        public SignOut(SignInManager<CognitoUser> signInManager, ILogger<LogoutModel> logger)
        {
            this._signInManager = signInManager;
            this._logger = logger;
        }
        public async Task<IActionResult> OnGet()
        {
            await this._signInManager.SignOutAsync();
            return RedirectToPage("/Index");
        }
    }
}