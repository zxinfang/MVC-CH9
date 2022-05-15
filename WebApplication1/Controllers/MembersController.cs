using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using WebApplication1.Security;
using WebApplication1.Serivces;
using WebApplication1.ViewModels;

namespace WebApplication1.Controllers
{
    public class MembersController : Controller
    {
        private readonly MembersDBService memberService = new MembersDBService();
        private readonly MailService mailService = new MailService();
        // GET: Members
        public ActionResult Index()
        {
            return View();
        }

        #region 註冊
        public ActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Gusetbooks");
            }
            return View();
        }
        [HttpPost]
        public ActionResult Register(RegisterViewModel RegisterMember)
        {
            if (ModelState.IsValid)
            {
                RegisterMember.newMember.Password = RegisterMember.Password;
                string AuthCode = mailService.GetAuthCode();
                RegisterMember.newMember.AuthCode = AuthCode;
                memberService.Register(RegisterMember.newMember);
                string TempMail = System.IO.File.ReadAllText(Server.MapPath("~/Views/Shared/TempMail.html"));
                UriBuilder ValidateUrl = new UriBuilder(Request.Url)
                {
                    Path = Url.Action("EmailValidate", "Members", new { Account = RegisterMember.newMember.Account, AuthCode = AuthCode })
                };
                string MailBody = mailService.GetMailBody(TempMail, RegisterMember.newMember.Account, ValidateUrl.ToString().Replace("%3F", "?"));
                mailService.SendMail(MailBody, RegisterMember.newMember.Email);
                TempData["RegisterState"] = "帳號註冊成功，請去收信以驗證Emial";
                return RedirectToAction("RegisterResult");
            }
            RegisterMember.Password = null;
            RegisterMember.PasswordCheck = null;
            return View(RegisterMember);
        }
        #endregion

        #region 註冊結果
        public ActionResult RegisterResult()
        {
            return View();
        }
        #endregion

        #region 帳號確認
        public JsonResult AccountCheck(RegisterViewModel registerMember)
        {
            return Json(memberService.AccountCheck(registerMember.newMember.Account), JsonRequestBehavior.AllowGet);
        }
        #endregion

        #region 信箱驗證
        public ActionResult EmailValidate(string Account,string AuthCode)
        {
            ViewData["EmailValidate"] = memberService.EmailValidate(Account, AuthCode);
            return View();
        }
        #endregion

        #region 登入
        public ActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Guestbooks");
            }
            return View();
        }
        [HttpPost]
        public ActionResult Login(LoginViewModel loginMember)
        {
            string str = memberService.LoginCheck(loginMember.Account, loginMember.Password);
            if (string.IsNullOrEmpty(str))
            {
                string role = memberService.GetRole(loginMember.Account);
                string cookieName = WebConfigurationManager.AppSettings["CookieName"];
                JwtService jwtService = new JwtService();
                string token = jwtService.GenerateToken(loginMember.Account, role);
                HttpCookie cookie = new HttpCookie(cookieName);
                cookie.Value = Server.UrlEncode(token);
                Response.Cookies.Add(cookie);
                Response.Cookies[cookieName].Expires = DateTime.Now.AddMinutes(Convert.ToInt32(WebConfigurationManager.AppSettings["ExpireMinute"]));
                return RedirectToAction("Index", "Guestbooks");
            }
            else
            {
                ModelState.AddModelError("", str);
                return View(loginMember);
            }
        }
        #endregion

        #region 修改密碼
        public ActionResult ChangePassword()
        {
            return View();
        }
        [HttpPost]
        [Authorize]
        public ActionResult ChangePassword(ChangePasswordViewModel changeMember)
        {
            if (ModelState.IsValid)
            {
                ViewData["ChangeState"] = memberService.ChangePassword(User.Identity.Name, changeMember.Password, changeMember.newPassword);
            }
            return View();
        }
        #endregion

        #region 登出
        [Authorize]
        public ActionResult Logout()
        {
            string cookieName = WebConfigurationManager.AppSettings["CookieName"];
            HttpCookie cookie = new HttpCookie(cookieName);
            cookie.Expires =DateTime.Now.AddDays(-1);
            cookie.Values.Clear();
            Response.Cookies.Set(cookie);
            return RedirectToAction("Login");
        }
        #endregion
    }
}