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
    public class Delete : PageModel
    {
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;
        private readonly SignInManager<CognitoUser> _signInManager;
        public Delete(
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
            public string Password { get; set; }
        }
        public bool isValidate()
        {

            //現在のパスワード
            if (this.Input.Password == null) { this.Input.Password = string.Empty; }
            if (this.Input.Password.Length == 0)
            {
                this.ModelState.AddModelError("Input.OldPassword", "必須項目です。");
            }
            if (this.Input.Password.Length < 8)
            {
                this.ModelState.AddModelError("Input.OldPassword", "8文字以上必要です。");
            }
            if (
                this.Input.Password.Length > 256)
            {
                this.ModelState.AddModelError("Input.OldPassword", "制限文字数を超過しています。");
            }
            if (!Regex.IsMatch(this.Input.Password, @"^[a-zA-Z\d!""#$%&'()*+,-./:;<=>?@[\]^_`{|}~]+$"))
            {
                this.ModelState.AddModelError("Input.OldPassword", "無効な文字が使用されています。");
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
                var result1 = await this._userManager.CheckPasswordAsync(user, this.Input.Password);
                if (result1 != null)
                {
                    var result2 = await this._userManager.DeleteAsync(user);
                    if (result2.Succeeded)
                    {
                        await this._signInManager.SignOutAsync();
                        return RedirectToPage("/Index");
                    }
                    foreach (var error in result2.Errors)
                    {
                        switch (error.Description)
                        {
                            case "Incorrect password":
                                break;
                            default:
                                this.ModelState.AddModelError(string.Empty, error.Description);
                                break;
                        }
                    }
                    return RedirectToPage("/Account/SignIn", new { mailaddress = email });
                }
                else
                {
                    this.ModelState.AddModelError("Input.Password", "パスワードが違います。");
                }
            }
            return Page();
        }
    }
}