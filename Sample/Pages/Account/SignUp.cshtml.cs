using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Amazon.AspNetCore.Identity.Cognito;//Add
using Amazon.Extensions.CognitoAuthentication;//Add
using Microsoft.AspNetCore.Identity;//Add
using Microsoft.Extensions.Logging;//Add
using System.ComponentModel.DataAnnotations;//Add
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;

namespace TheMyAsk.Web.Pages.Account
{
    [AllowAnonymous]
    public class SignUp : PageModel
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly ILogger<SignUp> _logger;
        private readonly CognitoUserPool _pool;
        public SignUp(
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
            public string MailAddress { get; set; }
            public string NickName { get; set; }
            public string NewPassword { get; set; }
            public string ConfirmPassword { get; set; }
        }
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

            //ニックネーム
            if (this.Input.NickName == null) { this.Input.NickName = string.Empty; }
            if (this.Input.NickName.Length == 0)
            {
                this.ModelState.AddModelError("Input.NickName", "必須項目です。");
            }
            if (this.Input.NickName.Length > 50)
            {
                this.ModelState.AddModelError("Input.NickName", "制限文字数を超過しています。");
            }

            //新しいパスワード
            if (this.Input.NewPassword == null) { this.Input.NewPassword = string.Empty; }
            if (this.Input.NewPassword.Length == 0)
            {
                this.ModelState.AddModelError("Input.NewPassword", "必須項目です。");
            }
            if (this.Input.NewPassword.Length < 8)
            {
                this.ModelState.AddModelError("Input.NewPassword", "8文字以上必要です。");
            }
            if (
                this.Input.NewPassword.Length > 256)
            {
                this.ModelState.AddModelError("Input.NewPassword", "制限文字数を超過しています。");
            }
            if (!Regex.IsMatch(this.Input.NewPassword, @"^[a-zA-Z\d!""#$%&'()*+,-./:;<=>?@[\]^_`{|}~]+$"))
            {
                this.ModelState.AddModelError("Input.NewPassword", "無効な文字が使用されています。");
            }

            //新しいパスワード（確認）
            if (this.Input.NewPassword == null) { this.Input.NewPassword = string.Empty; }
            if (this.Input.NewPassword.Length != 0 && this.Input.NewPassword != this.Input.ConfirmPassword)
            {
                this.ModelState.AddModelError("Input.NewPassword", "確認用パスワードと一致しません。");
            }
            return this.ModelState.ErrorCount == 0;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (this.isValidate() && this.ModelState.IsValid)
            {
                var user = this._pool.GetUser(this.Input.MailAddress);
                user.Attributes.Add(CognitoAttribute.Email.AttributeName, this.Input.MailAddress);
                user.Attributes.Add(CognitoAttribute.NickName.AttributeName, this.Input.NickName);
                var result = await this._userManager.CreateAsync(user, this.Input.NewPassword);
                if (result.Succeeded)
                {
                    return RedirectToPage("/Account/SignUpConfirm", new { mailaddress = this.Input.MailAddress });
                }
                foreach (var error in result.Errors)
                {
                    switch (error.Description)
                    {
                        case "Failed to create the Cognito User : An account with the given email already exists.":
                            this.ModelState.AddModelError("Input.MailAddress", "既に登録済みのメールアドレスです。");
                            break;
                        default:
                            this.ModelState.AddModelError(string.Empty, error.Description);
                            break;
                    }
                }
            }

            return Page();
        }
    }
}