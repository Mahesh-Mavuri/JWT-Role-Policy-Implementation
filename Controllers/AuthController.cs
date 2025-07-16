using JWTSelfAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTSelfAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous] // Allow unauthenticated access to this endpoint
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel login)
        {
            // Replace with your actual user authentication logic (e.g., database lookup, password hashing)
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var token = GenerateJwtTokenRoleBased(user);
                return Ok(new { token });
            }

            return Unauthorized("Invalid credentials.");
        }

        [AllowAnonymous] // Allow unauthenticated access to this endpoint
        [HttpPost("signin")]
        public IActionResult Signin([FromBody] LoginModel login)
        {
            // Replace with your actual user authentication logic (e.g., database lookup, password hashing)
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var token = GenerateJwtTokenPolicyBased(user);
                return Ok(new { token });
            }

            return Unauthorized("Invalid credentials.");
        }

        // This is a placeholder for your actual user authentication
        // In a real application, you'd verify against a database, use ASP.NET Core Identity, etc.
        private UserModel? AuthenticateUser(LoginModel login)
        {
            // Example: Hardcoded user for demonstration
            if (login.Username == "testuser" && login.Password == "password123")
            {
                return new UserModel { Username = login.Username, Role = "User" };
            }
            if (login.Username == "admin" && login.Password == "adminpassword")
            {
                return new UserModel { Username = login.Username, Role = "Admin" };
            }
            if (login.Username == "superadmin" && login.Password == "superadminpassword")
            {
                return new UserModel { Username = login.Username, Role = "Admin,User,Manager" };
            }
            if (login.Username == "manager" && login.Password == "managerpassword")
            {
                return new UserModel { Username = login.Username, Role = "Manager" };
            }
            return null;
        }

        private string GenerateJwtTokenRoleBased(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var roles = user.Role.Split(',').Select(role => role.Trim()).ToList();

            
            var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            // Add user roles as claims
            //new Claim(ClaimTypes.Role, user.Role)
        };
            // Add roles as claims
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
                // Alternatively, use a custom claim:
                // tokenDescriptor.Subject.AddClaim(new Claim("roles", role));
            }
            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_config["Jwt:ExpirationMinutes"] ?? "30")), // Token expiry
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateJwtTokenPolicyBased(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var roles = user.Role.Split(',').Select(role => role.Trim()).ToList();


            var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            // Add user roles as claims
            //new Claim(ClaimTypes.Role, user.Role)

            
            
        // Add DateOfBirth for demonstration (replace with actual user data)
        new Claim(ClaimTypes.DateOfBirth, "2000-01-15") // Example: User born Jan 15, 2000
        };
            // Add roles as claims
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
                // Alternatively, use a custom claim:
                // tokenDescriptor.Subject.AddClaim(new Claim("roles", role));
            }
            claims.Add(new Claim("permission", "can_view_dashboard"));
            claims.Add(new Claim("permission", "can_edit_product")); // User can have multiple "permission" claims

            claims.Add(new Claim("permission", "can_create_product")); // User can have multiple "permission" claims

            claims.Add(new Claim("permission", "can_delete_product")); // User can have multiple "permission" claims
            claims.Add(new Claim("permission", "can_view_logs")); // User can have multiple "permission" claims


            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_config["Jwt:ExpirationMinutes"] ?? "30")), // Token expiry
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
