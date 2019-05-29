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
    [Authorize]
    public class ChangePassword : PageModel
    {
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;
        private readonly SignInManager<CognitoUser> _signInManager;
        public ChangePassword(
            SignInManager<CognitoUser> signInManager,
            UserManager<CognitoUser> userManager,
            CognitoUserPool pool)
        {
            this._userManager = userManager as CognitoUserManager<CognitoUser>;
            this._pool = pool;
            this._signInManager = signInManager;
        }

        [BindProperty]
        public InputModel Input { get; set; }
        public class InputModel
        {
            public string OldPassword { get; set; }
            public string NewPassword { get; set; }
            public string ConfirmPassword { get; set; }
        }
        public bool isValidate()
        {

            //現在のパスワード
            if (this.Input.NewPassword == null) { this.Input.NewPassword = string.Empty; }
            if (this.Input.NewPassword.Length == 0)
            {
                this.ModelState.AddModelError("Input.OldPassword", "必須項目です。");
            }
            if (this.Input.NewPassword.Length < 8)
            {
                this.ModelState.AddModelError("Input.OldPassword", "8文字以上必要です。");
            }
            if (
                this.Input.NewPassword.Length > 256)
            {
                this.ModelState.AddModelError("Input.OldPassword", "制限文字数を超過しています。");
            }
            if (!Regex.IsMatch(this.Input.NewPassword, @"^[a-zA-Z\d!""#$%&'()*+,-./:;<=>?@[\]^_`{|}~]+$"))
            {
                this.ModelState.AddModelError("Input.OldPassword", "無効な文字が使用されています。");
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

        public IActionResult OnGet(string mailaddress = null)
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string action)
        {
            if (this.isValidate() && this.ModelState.IsValid)
            {
                var email = this.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email).Value;
                var user = this._pool.GetUser(email);
                var result = await this._userManager.ChangePasswordAsync(user, this.Input.OldPassword, this.Input.NewPassword);
                if (result.Succeeded)
                {
                    await this._signInManager.SignOutAsync();
                    return RedirectToPage("/Account/SignIn", new { mailaddress = email });
                }
                foreach (var error in result.Errors)
                {
                    switch (error.Description)
                    {
                        case "Incorrect password":
                            this.ModelState.AddModelError("Input.OldPassword", "パスワードが違います。");
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