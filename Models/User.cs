using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using System;

namespace bdapi_auth.Models
{
    public class User
    {
        // Basics
        [Key]
        public string Uid { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        // User info meta
        [Required]
        public string Username { get; set; }

        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        // Email confirmation
        [Required]
        public bool EmailConfirmed { get; set; }

        public string EmailConfirmationToken { get; set; }
        public string PasswordChangeToken { get; set; }

        // Engagement
        public DateTime CreationDate { get; set; }
        public DateTime LastLoginDate { get; set; }
    }

    public class NewUser
    {
        [EmailAddress]
        public string Email { get; set; }

        public string Password { get; set; }
        public string Username { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

    public class SigninUser
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class BasicUser
    {
        [Key]
        public string Uid { get; set; }

        [EmailAddress]
        public string Email { get; set; }

        public string Username { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}