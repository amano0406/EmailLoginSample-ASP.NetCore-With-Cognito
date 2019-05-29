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
    public class ResetPassword : PageModel
    {
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;
        public ResetPassword(
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
            if (this.isValidate() && this.ModelState.IsValid)
            {
                var user = this._pool.GetUser(this.Input.MailAddress);
                var result = await this._userManager.ResetPasswordAsync(user);
                if (result.Succeeded)
                {
                    return RedirectToPage("/Account/ResetPasswordConfirm", new { mailaddress = this.Input.MailAddress });
                }
                foreach (var error in result.Errors)
                {
                    switch (error.Description)
                    {
                        case "Failed to reset the Cognito User password : User does not exist.":
                            this.ModelState.AddModelError("Input.MailAddress", "不明なメールアドレスです。");
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