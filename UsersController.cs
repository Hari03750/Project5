using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Validation;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")] // Every action in this controller requires the Admin role.
public class UsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public UsersController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    [HttpGet]
    public IActionResult ListUsers()
    {
        // Only Id/UserName/Email are projected out — no password hashes,
        // security stamps, or other sensitive Identity fields leave this endpoint.
        var users = _userManager.Users
            .Select(u => new { u.Id, u.UserName, u.Email })
            .ToList();

        return Ok(users);
    }

    public class RoleAssignmentRequest
    {
        public string UserId { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
    }

    [HttpPost("assign-role")]
    public async Task<IActionResult> AssignRole([FromBody] RoleAssignmentRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.UserId) || string.IsNullOrWhiteSpace(request.Role))
        {
            return BadRequest("UserId and Role are required.");
        }

        // Only a fixed, known set of roles can ever be granted — this closes
        // off privilege escalation via an attacker-supplied arbitrary role name.
        var allowedRoles = new[] { "User", "Admin" };
        if (!allowedRoles.Contains(request.Role, StringComparer.Ordinal))
        {
            return BadRequest("Unknown role.");
        }

        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user is null)
        {
            return NotFound();
        }

        if (!await _roleManager.RoleExistsAsync(request.Role))
        {
            await _roleManager.CreateAsync(new IdentityRole(request.Role));
        }

        var result = await _userManager.AddToRoleAsync(user, request.Role);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors.Select(e => e.Description));
        }

        return Ok(new { message = $"Role '{request.Role}' assigned." });
    }
}
