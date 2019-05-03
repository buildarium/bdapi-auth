using Microsoft.EntityFrameworkCore;
using bdapi_auth.Models;

namespace bdapi_auth.Services
{
    public class UserService : DbContext
    {
        public UserService(DbContextOptions<UserService> options) : base(options)
        {
        }
        public DbSet<User> Users { get; set; }

    }
}