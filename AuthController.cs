using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.DTOs;
using SafeVault.Models;
using SafeVault.Services;
using SafeVault.Validation;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly TokenService _tokenService;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<ApplicationUser> signInManager,
        TokenService tokenService)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Model binding already enforces [Required]/[StringLength]/[EmailAddress].
        // We add explicit checks here too, so the same rules hold even if this
        // method is ever called from non-MVC code (defense in depth).
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        if (!InputValidator.IsValidUsername(request.UserName))
        {
            return BadRequest("Username must be 3-32 characters: letters, numbers, '.', '_', '-' only.");
        }

        if (!InputValidator.IsValidEmail(request.Email))
        {
            return BadRequest("Email address is not valid.");
        }

        if (!InputValidator.IsStrongPassword(request.Password))
        {
            return BadRequest("Password must be at least 8 characters and include upper, lower, digit, and symbol.");
        }

        var user = new ApplicationUser
        {
            UserName = request.UserName,
            Email = request.Email,
            // Sanitized even though this is never rendered as HTML today —
            // protects any future view/report that displays it.
            DisplayName = InputValidator.SanitizeHtml(request.DisplayName)
        };

        // UserManager.CreateAsync stores a salted hash (PBKDF2) — plaintext
        // passwords are never persisted.
        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors.Select(e => e.Description));
        }

        // Every new self-registered account gets the least-privileged role.
        // Admin role can only be granted by an existing Admin via the
        // UsersController RBAC endpoint below — never at self-registration.
        const string defaultRole = "User";
        if (!await _roleManager.RoleExistsAsync(defaultRole))
        {
            await _roleManager.CreateAsync(new IdentityRole(defaultRole));
        }
        await _userManager.AddToRoleAsync(user, defaultRole);

        return Ok(new { message = "Registration successful." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        var user = await _userManager.FindByNameAsync(request.UserName);

        // Same generic error whether the username doesn't exist or the
        // password is wrong, so the endpoint can't be used to enumerate
        // valid usernames.
        const string genericError = "Invalid username or password.";

        if (user is null)
        {
            return Unauthorized(genericError);
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            return Unauthorized(genericError);
        }

        var roles = await _userManager.GetRolesAsync(user);
        var token = _tokenService.CreateToken(user, roles);

        return Ok(new { token, roles });
    }
}
