using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using bdapi_auth.Models;
using bdapi_auth.Services;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace bdapi_auth.Controllers
{
    [Route("auth")]
    [EnableCors("MyPolicy")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private UserService _userService;

        public UsersController(UserService userService)
        {
            _userService = userService;
        }

        // GET /auth/users
        // Get a list of all users -- for debugging purposes only
        // TODO: Remove
        [HttpGet("users")]
        public IEnumerable<User> GetUsers()
        {
            return _userService.Users.AsEnumerable();
        }

        // GET /auth/id/{id}
        // Get a user's info based off of their uid
        [HttpGet("id/{id}")]
        public ActionResult<User> GetById(string id)
        {
            // TODO: Don't return so much unnecessary shit
            return _userService.Users.Find(id);
        }

        // POST /auth/signup
        // Create a new user
        [HttpPost("signup")]
        public BasicUser PostNewUser([FromBody] NewUser usr)
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
            if (Environment.GetEnvironmentVariable("ENV") == "prod")
            {
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
                var response = client.SendEmailAsync(msg);
            }

            User CreatedUser = _userService.Users.Single(u => u.Username == usr.Username);

            return new BasicUser
            {
                Uid = CreatedUser.Uid,
                Email = CreatedUser.Email,
                Username = CreatedUser.Username,
                FirstName = CreatedUser.FirstName,
                LastName = CreatedUser.LastName
            };
        }

        // POST auth/signin
        // Sign in as a user, receiving an Authorization Token
        [HttpPost("signin")]
        public Dictionary<string, object> PostSignIn(SigninUser usr)
        {
            // Find user with username
            User FoundUser = _userService.Users.SingleOrDefault(u => u.Username == usr.Username);

            // If that username doesn't exist
            if (FoundUser == null)
            {
                // Return 401
                Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return new Dictionary<string, object>
                {
                    { "error", "Incorrect signin credentials" }
                };
            }

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

            // Check if the passwords match
            if (BCrypt.Net.BCrypt.Verify(usr.Password, FoundUser.Password))
            {
                // Must have confirmed email
                if (!FoundUser.EmailConfirmed)
                {
                    // Return 400
                    Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    return new Dictionary<string, object>
                    {
                        { "error", "Must confirm email before signin" }
                    };
                }

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
                AuthorizationToken Token = _userService.AuthorizationTokens.FirstOrDefault(t => t.User == FoundUser);
                BasicUser RetUser = new BasicUser
                {
                    Uid = FoundUser.Uid,
                    Email = FoundUser.Email,
                    Username = FoundUser.Username,
                    FirstName = FoundUser.FirstName,
                    LastName = FoundUser.LastName
                };
                return new Dictionary<string, object>
                {
                    { "user", RetUser },
                    { "token", Token.Uid },
                    { "expiration", Token.ExpirationDate }
                };
            }
            else
            {
                // Wrong password
                // Return 401
                Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return new Dictionary<string, object>
                {
                    { "error", "Incorrect signin credentials" }
                };
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

        // GET auth/uid
        // Get a user's UID based off of a supplied Authorization Token
        [HttpGet("uid")]
        public string GetMyUid()
        {
            AuthorizationToken AuthTok = _userService.AuthorizationTokens.Single(
                t => t.Uid == Request.Headers["Authorization"]
            );
                
            return AuthTok.UserUid;
        }
        
        // GET auth/me
        // Get your user info
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
        // Change your info
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
                if (Environment.GetEnvironmentVariable("ENV") == "prod")
                {
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
                    var response = client.SendEmailAsync(msg);
                }

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
        // Trigger forgot password process
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
            if (Environment.GetEnvironmentVariable("ENV") == "prod")
            {
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
                var response = client.SendEmailAsync(msg);
            }

            _userService.SaveChanges();
        }

        // PUT auth/forgot
        // Reset password
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

        // TODO: Make it a get and return a string
        // PUT auth/email
        // Confirm email
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
