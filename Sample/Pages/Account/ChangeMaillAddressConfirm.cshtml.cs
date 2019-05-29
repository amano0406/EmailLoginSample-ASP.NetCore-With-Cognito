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
    public class ChangeMaillAddressConfirm : PageModel
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly ILogger<SignUp> _logger;
        private readonly CognitoUserPool _pool;
        public ChangeMaillAddressConfirm(
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
            public string Code { get; set; }
        }

        public bool isValidateConfirm()
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

            //確認コード
            //if (this.Input.Code == null) { this.Input.Code = string.Empty; }
            //if (this.Input.Code.Length == 0)
            //{
            //    this.ModelState.AddModelError("Input.Code", "必須項目です。");
            //}
            //if (
            //    this.Input.Code.Length > 10)
            //{
            //    this.ModelState.AddModelError("Input.Code", "制限文字数を超過しています。");
            //}
            //if (!Regex.IsMatch(this.Input.Code, @"^[0-9]+$"))
            //{
            //    this.ModelState.AddModelError("Input.Code", "無効な文字が使用されています。");
            //}

            return this.ModelState.ErrorCount == 0;
        }

        public bool isValidateReSend()
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
            if (action == "Confirm")
            {
                if (this.isValidateConfirm() && this.ModelState.IsValid)
                {
                    var email = this.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email).Value;
                    var user = this._pool.GetUser(email);
                    var result = await this._userManager.ChangeEmailAsync(user, this.Input.NewMailAddress, this.Input.Code);
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
            else if (action == "ReSend")
            {
                if (this.isValidateReSend() && this.ModelState.IsValid)
                {
                    var email = this.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email).Value;
                    var user = this._pool.GetUser(email);
                    var result = await this._userManager.SendEmailConfirmationTokenAsync(user);
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