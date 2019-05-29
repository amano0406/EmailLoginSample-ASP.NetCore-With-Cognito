using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.V3.Pages.Account.Internal;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace TheMyAsk.Web.Pages.Account
{
    [AllowAnonymous]
    public class SignIn : PageModel
    {
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;

        public SignIn(
            UserManager<CognitoUser> userManager,
            SignInManager<CognitoUser> signInManager,
            ILogger<LoginModel> logger)
        {
            this._userManager = userManager as CognitoUserManager<CognitoUser>;
            this._signInManager = signInManager;
            this._logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }
        public class InputModel
        {
            public string MailAddress { get; set; }
            public string Password { get; set; }
            public bool RememberMe { get; set; }
        }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public bool isValidate()
        {
            //メールアドレス
            if (this.Input.MailAddress == null) { this.Input.MailAddress = string.Empty; }
            if (this.Input.MailAddress.Length == 0)
            {
                this.ModelState.AddModelError("Input.MailAddress", "必須項目です。");
            }
            if (
                !Regex.IsMatch(this.Input.MailAddress,
                @"^(?("")("".+?(?<!\\)""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))" +
                @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-0-9a-z]*[0-9a-z]*\.)+[a-z0-9][\-a-z0-9]{0,22}[a-z0-9]))$",
                RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250))
            )
            {
                this.ModelState.AddModelError("Input.MailAddress", "正しいメールアドレスを入力してください。");
            }
            if (this.Input.MailAddress.Length > 100)
            {
                this.ModelState.AddModelError("Input.MailAddress", "制限文字数を超過しています。");
            }

            //新しいパスワード
            if (this.Input.Password == null) { this.Input.Password = string.Empty; }
            if (this.Input.Password.Length == 0)
            {
                this.ModelState.AddModelError("Input.Password", "必須項目です。");
            }
            if (this.Input.Password.Length < 8)
            {
                this.ModelState.AddModelError("Input.Password", "8文字以上必要です。");
            }
            if (
                this.Input.Password.Length > 256)
            {
                this.ModelState.AddModelError("Input.Password", "制限文字数を超過しています。");
            }
            if (!Regex.IsMatch(this.Input.Password, @"^[a-zA-Z\d!""#$%&'()*+,-./:;<=>?@[\]^_`{|}~]+$"))
            {
                this.ModelState.AddModelError("Input.Password", "無効な文字が使用されています。");
            }

            return this.ModelState.ErrorCount == 0;
        }

        public IActionResult OnGet(string mailaddress = null)
        {
            if (mailaddress != null)
            {
                this.Input = new InputModel();
                this.Input.MailAddress = mailaddress;
            }

            // クリーンなログインプロセスを確実にするために既存の外部クッキーをクリアする
            //await this.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false);
            //this.ExternalLogins = (await this._signInManager.GetExternalAuthenticationSchemesAsync().ConfigureAwait(false)).ToList();

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {

            if (this.isValidate() && this.ModelState.IsValid)
            {
                var result = await this._signInManager.PasswordSignInAsync(this.Input.MailAddress, this.Input.Password, this.Input.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    return RedirectToPage("/Index");
                }
                else
                {
                    this.ModelState.AddModelError(string.Empty, "メールアドレスまたはパスワードが違います。");
                }
            }
            return Page();
        }
    }
}