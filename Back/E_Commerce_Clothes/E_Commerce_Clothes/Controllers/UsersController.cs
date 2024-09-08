using E_Commerce_Clothes.DTO;
using E_Commerce_Clothes.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace E_Commerce_Clothes.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private MyDbContext _db;
        private readonly ILogger<UsersController> _logger;
        private readonly TokenGeneratorDTO _tokenGenerator;

        public UsersController(MyDbContext db, ILogger<UsersController> logger, TokenGeneratorDTO tokenGenerator)
        {

            _db = db;
            _logger = logger;
            _tokenGenerator = tokenGenerator;
        }


        [HttpGet]
        [Route("All/Users")]
        // [ProducesResponseType(200, Type = typeof())]
        [ProducesResponseType(400)]
        [ProducesResponseType(204)]
        [ProducesResponseType(500)]
        [ProducesResponseType(404)]

        public IActionResult Get() {

            var user = _db.Users.ToList();

            return Ok();
        }


        ///////////////////////////////////////////////////////////

        [HttpPost]
        [Route("register")]
        // [ProducesResponseType(200, Type = typeof())]
        [ProducesResponseType(400)]
        [ProducesResponseType(204)]
        [ProducesResponseType(500)]
        [ProducesResponseType(404)]
        
        public IActionResult Register([FromForm] UserHashDTO model)
        {
            if (model.Password != model.ConfirmPassword)
            {
                return BadRequest();
            }


            byte[] passwordHash, passwordSalt;
            PasswordHashDTO.CreatePasswordHash(model.Password, out passwordHash, out passwordSalt);
            User user = new User
            {
                Name = model.Name,
                Email = model.Email,
                Password = model.Password,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt
            };

            _db.Users.Add(user);
            _db.SaveChanges();
            //For Demo Purpose we are returning the PasswordHash and PasswordSalt
            return Ok(user);
        }

        ////////////////////////////////////////////////////////////////////////////////


        [HttpPost]
        [Route("login")]
        [ProducesResponseType(400)]
        [ProducesResponseType(204)]
        [ProducesResponseType(500)]
        [ProducesResponseType(404)]
        public IActionResult Login([FromForm] LoginDTO model)
        {
            var user = _db.Users.FirstOrDefault(x => x.Email == model.Email);

            if (user == null || !PasswordHashDTO.VerifyPasswordHash(model.Password, user.PasswordHash, user.PasswordSalt))
            {
                return Unauthorized("Invalid username or password.");
            }

            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }

        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
        new Claim(JwtRegisteredClaimNames.Sub, user.Email),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.Name, user.Name)
    };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("YourSuperSecureLongKeyForJWT12345"));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "yourapp.com",
                audience: "yourapp.com",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        ///
        /// ///////////////////////////////////////////////
  
        [HttpPost]
        [Route("google-login")]
        [ProducesResponseType(400)]
        [ProducesResponseType(200)]
        [ProducesResponseType(500)]
        public IActionResult GoogleLogin([FromForm] GoogleLoginDTO model)
        {
            var user = _db.Users.FirstOrDefault(x => x.Email == model.Email);

            if (user == null)
            {
                user = new User
                {
                    Name = model.Name,
                    Email = model.Email,
                    //ProfilePicture = model.ProfilePicture
                };

                _db.Users.Add(user);
                _db.SaveChanges();
            }

            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }

        
    }
}
