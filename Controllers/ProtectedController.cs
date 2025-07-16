using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JWTSelfAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // All actions in this controller require authorization
    public class ProtectedController : ControllerBase
    {
        // ... (GetProtectedData method)

        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")] // Only users whose JWT contains a ClaimTypes.Role with value "Admin" can access
        public IActionResult GetAdminData()
        {
            return Ok("This data is only accessible by administrators.");
        }

        [HttpGet("editor-or-admin")]
        [Authorize(Roles = "Editor,Admin")] // Users with "Editor" OR "Admin" roles can access
        public IActionResult GetEditorOrAdminData()
        {
            return Ok("This data is accessible by editors or administrators.");
        }

        [HttpGet("manager")]
        // If a user needs multiple roles, you can apply multiple [Authorize] attributes (AND logic)
        // Or, for OR logic (like "Editor,Admin"), specify them in a comma-separated list.
        [Authorize(Roles = "Manager")]
        public IActionResult GetManagerData()
        {
            return Ok("This is for managers only.");
        }
        [HttpGet]
        public IActionResult GetProtectedData()
        {
            var username = User?.Identity?.Name; // Access the authenticated user's name
            var role = User?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value; // Access user roles

            return Ok($"Hello {username}! You are authenticated and your role is: {role}. This is protected data.");
        }

       
        [HttpGet("user-or-admin")]
        [Authorize(Roles = "User,Admin")] // Users with "User" or "Admin" roles can access this
        public IActionResult GetUserOrAdminData()
        {
            return Ok("This data is accessible by users or administrators.");
        }
    }
}
