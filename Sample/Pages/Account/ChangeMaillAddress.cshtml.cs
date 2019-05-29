using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;//Add
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;//Add
using Amazon.Extensions.CognitoAuthentication;//Add
using Microsoft.AspNetCore.Authorization;//Add
using Microsoft.AspNetCore.Identity;//Add
using Microsoft.AspNetCore.Mvc;//Add
using Microsoft.AspNetCore.Mvc.RazorPages;//Add
using Microsoft.Extensions.Logging;

namespace TheMyAsk.Web.Pages.Account
{
    [Authorize]
    public class ChangeMaillAddress : PageModel
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly ILogger<SignUp> _logger;
        private readonly CognitoUserPool _pool;
        public ChangeMaillAddress(
            UserManager<CognitoUser> userManager,
            SignInManager<CognitoUser> signInManager,
            ILogger<SignUp> logger,
            CognitoUserPool pool)
        {
            this._userManager = userManager as CognitoUserManager<CognitoUser>;
            this._signInManager = signInManager;
            this._logger = logger;
            this._pool = pool;
        }

        [BindProperty]
        public InputModel Input { get; set; }
        public class InputModel
        {
            public string NewMailAddress { get; set; }
        }
        public bool isValidate()
        {
            //メールアドレス
            if (this.Input.NewMailAddress == null) { this.Input.NewMailAddress = string.Empty; }
            if (this.Input.NewMailAddress.Length == 0)
            {
                this.ModelState.AddModelError("Input.NewMailAddress", "必須項目です。");
            }
            if (
                !Regex.IsMatch(this.Input.NewMailAddress,
                @"^(?("")("".+?(?<!\\)""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))" +
                @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-0-9a-z]*[0-9a-z]*\.)+[a-z0-9][\-a-z0-9]{0,22}[a-z0-9]))$",
                RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250))
            )
            {
                this.ModelState.AddModelError("Input.NewMailAddress", "正しいメールアドレスを入力してください。");
            }
            if (this.Input.NewMailAddress.Length > 100)
            {
                this.ModelState.AddModelError("Input.NewMailAddress", "制限文字数を超過しています。");
            }

            return this.ModelState.ErrorCount == 0;
        }

        public IActionResult OnGet(string mailaddress = null)
        {
            if (mailaddress != null)
            {
                this.Input = new InputModel();
                this.Input.NewMailAddress = mailaddress;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string action)
        {
            if (this.isValidate() && this.ModelState.IsValid)
            {
                var email = this.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email).Value;
                var user = this._pool.GetUser(email);
                var result = await this._userManager.SetEmailAsync(user, this.Input.NewMailAddress);
                if (result.Succeeded)
                {
                    return RedirectToPage("/Account/ChangeMaillAddressConfirm", new { mailaddress = email });
                }
                foreach (var error in result.Errors)
                {
                    switch (error.Description)
                    {
                        default:
                            this.ModelState.AddModelError(string.Empty, error.Description);
                            break;
                    }
                }
                return RedirectToPage("/Account/ChangeMaillAddressConfirm", new { mailaddress = this.Input.NewMailAddress });
            }
            return Page();
        }
    }
}