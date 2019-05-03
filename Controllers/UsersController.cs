using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using bdapi_auth.Models;
using bdapi_auth.Services;
using Microsoft.AspNetCore.Mvc;

namespace bdapi_auth.Controllers
{
    [Route("users")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private UserService _userService;

        public UsersController(UserService userService)
        {
            _userService = userService;
        }

        // GET api/values
        [HttpGet]
        public IEnumerable<User> Get()
        {
            return _userService.Users.AsEnumerable();
        }

        // GET api/values/5
        [HttpGet("{id}")]
        public ActionResult<string> Get(int id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
