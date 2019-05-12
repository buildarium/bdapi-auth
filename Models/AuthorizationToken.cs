using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace bdapi_auth.Models
{
    public class AuthorizationToken
    {
        // Basics
        [Key]
        public string Uid { get; set; }

        [Required]
        public string UserUid { get; set; }

        [ForeignKey("UserUid")]
        public User User { get; set; }

        [Required]
        public DateTime CreationDate { get; set; }

        [Required]
        public DateTime ExpirationDate { get; set; }
    }
}