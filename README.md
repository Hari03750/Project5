# SafeVault

A small ASP.NET Core Web API built as the capstone for the *Security and
Authentication* course. It demonstrates secure input handling, SQL-injection
prevention, JWT-based authentication with role-based access control (RBAC),
and fixes for vulnerabilities (SQL injection, stored XSS, and an IDOR/broken
access control issue) found during a debugging pass.

## Project structure

```
SafeVault.sln
src/SafeVault/
  Program.cs                  App startup: Identity, JWT auth, RBAC policies, security headers
  Data/SafeVaultDbContext.cs  EF Core context (parameterized queries by default)
  Data/UsersLookupRepository.cs  Raw ADO.NET example showing the SQLi fix (parameter binding)
  Models/                     ApplicationUser (Identity), VaultItem
  DTOs/                       Request models with data-annotation validation
  Validation/InputValidator.cs  Centralized validation + HTML sanitization
  Controllers/
    AuthController.cs         Register / login, issues JWTs, assigns default "User" role
    UsersController.cs        Admin-only endpoints, RBAC role assignment
    VaultController.cs        Authenticated CRUD with per-resource ownership checks
tests/SafeVault.Tests/
  InputValidationTests.cs     Unit tests for validation/sanitization rules
  SqlInjectionTests.cs        Proves parameterized queries resist injection payloads
  AuthorizationTests.cs       End-to-end RBAC + IDOR-prevention tests via WebApplicationFactory
SECURITY_SUMMARY.md           Vulnerabilities found, fixes applied, how Copilot helped
```

## Running locally

```bash
dotnet restore
dotnet build

# Run the API
dotnet run --project src/SafeVault

# Run the test suite
dotnet test
```

Set a real signing secret before running outside of local testing:

```bash
export Jwt__Key="a-long-random-secret-at-least-32-bytes"
```

## Key security features

- **Input validation** — data annotations on every request DTO plus a
  centralized `InputValidator` (username/email/password rules, length caps,
  suspicious-SQL-pattern detection, HTML sanitization).
- **SQL injection prevention** — EF Core LINQ queries (auto-parameterized)
  everywhere, and one raw ADO.NET example (`UsersLookupRepository`) that
  binds all input as SQL parameters instead of concatenating strings.
- **Authentication** — ASP.NET Core Identity for salted/hashed password
  storage, account lockout after repeated failures, JWT bearer tokens for
  API access.
- **Authorization / RBAC** — `[Authorize(Roles = "Admin")]` on admin-only
  endpoints, a fixed allow-list of grantable roles, and per-resource
  ownership checks (so "User" role alone isn't enough to touch someone
  else's data).
- **XSS prevention** — free-text fields are HTML-sanitized before storage,
  API responses are plain JSON (safely encoded), and `Content-Security-Policy`
  / `X-Content-Type-Options` / `X-Frame-Options` headers are set on every
  response.

See `SECURITY_SUMMARY.md` for the specific vulnerabilities identified during
the debugging activity and how each was fixed.
