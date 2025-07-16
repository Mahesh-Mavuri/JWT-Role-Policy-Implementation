using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JWTSelfAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ManagementController : ControllerBase
    {
        [HttpGet("dashboard")]
        [Authorize(Policy = "CanViewDashboard")] // Requires the "CanViewDashboard" policy
        public IActionResult GetDashboardSummary()
        {
            var username = User?.Identity?.Name;
            var permissions = new List<string>();
            permissions =  User?.Claims
                                  .Where(c => c.Type == "permission")
                                  .Select(c => c.Value)
                                  .ToList();

            return Ok($"Dashboard summary for {username}. Permissions: {string.Join(", ", permissions)}");
        }

        [HttpPost("products")]
        [Authorize(Policy = "CanManageProducts")] // Requires the "CanManageProducts" policy
        public IActionResult CreateProduct()
        {
            return Ok("Product created successfully.");
        }

        [HttpGet("admin-logs")]
        [Authorize(Policy = "AdminAndCanViewLogs")] // Requires the "AdminAndCanViewLogs" policy
        public IActionResult GetAdminLogs()
        {
            return Ok("Admin logs accessed.");
        }

        [HttpGet("age-restricted")]
        [Authorize(Policy = "MinimumAge18")] // Requires the "MinimumAge18" policy
        public IActionResult GetAgeRestrictedContent()
        {
            // In a real scenario, the age would be a claim in the JWT
            var userAgeClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.DateOfBirth);
            // You'd parse this to DateTime and calculate age for the policy handler
            return Ok("Access granted to age-restricted content.");
        }
    }
}
