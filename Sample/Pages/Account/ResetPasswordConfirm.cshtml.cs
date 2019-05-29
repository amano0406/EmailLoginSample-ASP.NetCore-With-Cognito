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

namespace TheMyAsk.Web.Pages.Account
{
    [AllowAnonymous]
    public class ResetPasswordConfirm : PageModel
    {
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;
        public ResetPasswordConfirm(
            UserManager<CognitoUser> userManager,
            CognitoUserPool pool)
        {
            this._userManager = userManager as CognitoUserManager<CognitoUser>;
            this._pool = pool;
        }

        [BindProperty]
        public InputModel Input { get; set; }
        public class InputModel
        {
            public string MailAddress { get; set; }
            public string Code { get; set; }
            public string NewPassword { get; set; }
            public string ConfirmPassword { get; set; }
        }

        public bool isValidateConfirm()
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

            //確認コード
            if (this.Input.Code == null) { this.Input.Code = string.Empty; }
            if (this.Input.Code.Length == 0)
            {
                this.ModelState.AddModelError("Input.Code", "必須項目です。");
            }
            if (
                this.Input.Code.Length > 10)
            {
                this.ModelState.AddModelError("Input.Code", "制限文字数を超過しています。");
            }
            if (!Regex.IsMatch(this.Input.Code, @"^[0-9]+$"))
            {
                this.ModelState.AddModelError("Input.Code", "無効な文字が使用されています。");
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

        public bool isValidateReSend()
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

            return this.ModelState.ErrorCount == 0;
        }

        public IActionResult OnGet(string mailaddress = null)
        {
            if (mailaddress != null)
            {
                this.Input = new InputModel();
                this.Input.MailAddress = mailaddress;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string action)
        {
            if (action == "Confirm")
            {
                if (this.isValidateConfirm() && this.ModelState.IsValid)
                {
                    var user = this._pool.GetUser(this.Input.MailAddress);
                    var result = await this._userManager.ResetPasswordAsync(user, this.Input.Code, this.Input.NewPassword);
                    if (result.Succeeded)
                    {
                        return RedirectToPage("/Account/SignIn", new { this.Input.MailAddress });
                    }
                    foreach (var error in result.Errors)
                    {
                        switch (error.Description)
                        {
                            case "Failed to change the Cognito User password : Invalid verification code provided, please try again.":
                                this.ModelState.AddModelError("Input.Code", "確認コードが違います。");
                                break;
                            default:
                                this.ModelState.AddModelError(string.Empty, error.Description);
                                break;
                        }
                    }
                }
            }
            else if (action == "ReSend")
            {
                if (this.isValidateReSend() && this.ModelState.IsValid)
                {
                    var user = this._pool.GetUser(this.Input.MailAddress);
                    var result = await this._userManager.ResetPasswordAsync(user);
                    if (result.Succeeded)
                    {
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
                }
            }
            return Page();
        }
    }
}