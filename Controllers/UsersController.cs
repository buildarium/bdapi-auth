using System;
using System.Collections.Generic;
using System.Linq;
using bdapi_auth.Models;
using bdapi_auth.Services;
using Microsoft.AspNetCore.Mvc;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace bdapi_auth.Controllers
{
    [Route("auth")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private UserService _userService;

        public UsersController(UserService userService)
        {
            _userService = userService;
        }

        // GET /auth/users
        [HttpGet("users")]
        public IEnumerable<User> GetUsers()
        {
            return _userService.Users.AsEnumerable();
        }

        // GET /auth/id/{id}
        [HttpGet("id/{id}")]
        public ActionResult<User> GetById(string id)
        {
            return _userService.Users.Find(id);
        }

        // POST /auth/signup
        [HttpPost("signup")]
        public void PostNewUser([FromBody] NewUser usr)
        {
            // Does a user with this email or username already exist?
            User DupCheckEmail = _userService.Users.SingleOrDefault(u => u.Email == usr.Email);
            User DupCheckUsername = _userService.Users.SingleOrDefault(u => u.Username == usr.Username);

            if (DupCheckEmail != null || DupCheckUsername != null)
            {
                throw new ArgumentException();
            }

            // Hash password
            string Pwd = BCrypt.Net.BCrypt.HashPassword(usr.Password);

            // Generate email verification token
            Guid g = Guid.NewGuid();
            string EmailToken = Convert.ToBase64String(g.ToByteArray());
            EmailToken = EmailToken.Replace("=", "");
            EmailToken = EmailToken.Replace("+", "");
            EmailToken = EmailToken.Replace("/", "");

            // Save new user
            _userService.Add(new User
            {
                Email = usr.Email,
                Username = usr.Username,
                FirstName = usr.FirstName,
                LastName = usr.LastName,
                Password = Pwd,
                EmailConfirmed = false,
                EmailConfirmationToken = EmailToken,
                CreationDate = DateTime.Now,
                LastLoginDate = DateTime.Now
            });
            _userService.SaveChanges();

            // Send confirmation email
            var apiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY");
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("buck@buildarium.com", "Buck Tower");
            var subject = "Confirm your Buildarium account, " + usr.FirstName;
            var to = new EmailAddress(usr.Email, usr.FirstName + " " + usr.LastName);
            var plainTextContent = "Confirm your email by visiting this link: https://app.buildarium.com/confirm/" +
                EmailToken;
            var htmlContent = "<strong>Confirm your email by visiting this link:</strong> https://app.buildarium.com/confirm/" +
                EmailToken;
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            //var response = client.SendEmailAsync(msg);
        }

        // POST auth/signin
        [HttpPost("signin")]
        public string PostSignIn(SigninUser usr)
        {
            // Find user with username
            User FoundUser = _userService.Users.Single(u => u.Username == usr.Username);

            // Clear expired tokens -- doesn't actually execute until SaveChanges()
            var ExpTokens = _userService.AuthorizationTokens
                .Where(
                    t => t.UserUid == FoundUser.Uid &&
                    t.ExpirationDate < DateTime.Now
                )
                .ToList();
            foreach (AuthorizationToken token in ExpTokens)
            {
                _userService.Remove(token);
            }

            // Must have confirmed email
            if (!FoundUser.EmailConfirmed)
            {
                throw new ArgumentException();
            }

            // Check if the passwords match
            if (BCrypt.Net.BCrypt.Verify(usr.Password, FoundUser.Password))
            {
                // Correct password -- create a new token
                _userService.Add(new AuthorizationToken
                {
                    UserUid = FoundUser.Uid,
                    CreationDate = DateTime.Now,
                    ExpirationDate = DateTime.Now.AddDays(30)
                });
                _userService.SaveChanges();

                // TODO: return the newly minted token, not just the first
                // Return token
                return _userService.AuthorizationTokens.FirstOrDefault(t => t.User == FoundUser).Uid;
            }
            else
            {
                // Incorrect password
                throw new ArgumentException();
            }
        }

        // DELETE auth/signout
        [HttpDelete("signout")]
        public void Signout(int id)
        {
            // Find token
            AuthorizationToken AuthTok = _userService.AuthorizationTokens.Single(
                t => t.Uid == Request.Headers["Authorization"]
            );

            // Delete token
            _userService.AuthorizationTokens.Remove(AuthTok);
            _userService.SaveChanges();
        }

        // GET auth/me
        [HttpGet("me")]
        public NewUser GetMe()
        {
            AuthorizationToken AuthTok = _userService.AuthorizationTokens.Single(
                t => t.Uid == Request.Headers["Authorization"]
            );
                
            User usr = _userService.Users.Find(AuthTok.UserUid);

            return new NewUser
            {
                Email = usr.Email,
                Username = usr.Username,
                FirstName = usr.FirstName,
                LastName = usr.LastName
            };
        }

        // PUT auth/me
        [HttpPut("me")]
        public void PutMe([FromBody] NewUser usr)
        {
            AuthorizationToken AuthTok = _userService.AuthorizationTokens.Single(
                t => t.Uid == Request.Headers["Authorization"]
            );

            User FoundUser = _userService.Users.Find(AuthTok.UserUid);

            if (usr.Email != null && usr.Email != FoundUser.Email)
            {
                // User is trying to change their email
                // Check there are no dups
                int count = _userService.Users
                    .Where(u => u.Email == usr.Email)
                    .ToList().Count;
                if (count > 1)
                {
                    throw new ArgumentException();
                }

                // Need to confirm new email
                FoundUser.EmailConfirmed = false;
                // Generate email verification token
                Guid g = Guid.NewGuid();
                string EmailToken = Convert.ToBase64String(g.ToByteArray());
                EmailToken = EmailToken.Replace("=", "");
                EmailToken = EmailToken.Replace("+", "");
                EmailToken = EmailToken.Replace("/", "");

                // Send email
                var apiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY");
                var client = new SendGridClient(apiKey);
                var from = new EmailAddress("buck@buildarium.com", "Buck Tower");
                var subject = "Confirm your Buildarium account, " + usr.FirstName;
                var to = new EmailAddress(usr.Email, usr.FirstName + " " + usr.LastName);
                var plainTextContent = "Confirm your email by visiting this link: https://app.buildarium.com/confirm/" +
                    EmailToken;
                var htmlContent = "<strong>Confirm your email by visiting this link:</strong> https://app.buildarium.com/confirm/" +
                    EmailToken;
                var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
                //var response = client.SendEmailAsync(msg);

                FoundUser.Email = usr.Email;
            }

            if (usr.Username != null && usr.Username != FoundUser.Username)
            {
                // User is trying to change their username
                // Check there are no dups
                int count = _userService.Users
                    .Where(u => u.Username == usr.Username)
                    .ToList().Count;
                if (count > 1)
                {
                    throw new ArgumentException();
                }

                FoundUser.Username = usr.Username;
            }

            // Change other meta
            FoundUser.FirstName = usr.FirstName;
            FoundUser.LastName = usr.LastName;

            // Save all changes to Postgres
            _userService.SaveChanges();
        }

        // POST auth/forgot
        [HttpPost("forgot")]
        public void TriggerForgotPassword()
        {
            User FoundUser = _userService.Users.Single(u => u.Email == Request.Headers["email"]);

            // Generate password forgot token
            Guid g = Guid.NewGuid();
            string PasswordToken = Convert.ToBase64String(g.ToByteArray());
            PasswordToken = PasswordToken.Replace("=", "");
            PasswordToken = PasswordToken.Replace("+", "");
            PasswordToken = PasswordToken.Replace("/", "");

            FoundUser.PasswordChangeToken = PasswordToken;

            // Send change password email
            var apiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY");
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("buck@buildarium.com", "Buck Tower");
            var subject = "Change your Buildarium password, " + FoundUser.FirstName;
            var to = new EmailAddress(FoundUser.Email, FoundUser.FirstName + " " + FoundUser.LastName);
            var plainTextContent = "Change your password by visiting this link: https://app.buildarium.com/changepassword/" +
                PasswordToken;
            var htmlContent = "<strong>Change your password by visiting this link:</strong> https://app.buildarium.com/changepassword/" +
                PasswordToken;
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);

            _userService.SaveChanges();
        }

        // PUT auth/forgot
        [HttpPut("forgot/{token}")]
        public void ChangeForgotPassword(string token)
        {
            if (token == null)
            {
                throw new ArgumentException();
            }

            User FoundUser = _userService.Users.Single(u => u.PasswordChangeToken == token);

            FoundUser.Password = BCrypt.Net.BCrypt.HashPassword(Request.Headers["Password"]);

            _userService.SaveChanges();
        }

        // PUT auth/email
        [HttpPut("email/{token}")]
        public void ConfirmEmail(string token)
        {
            if (token == null)
            {
                throw new ArgumentException();
            }

            User FoundUser = _userService.Users.Single(u => u.EmailConfirmationToken == token);

            FoundUser.EmailConfirmed = true;
            Console.WriteLine(FoundUser.Email);

            _userService.SaveChanges();
        }
    }
}
