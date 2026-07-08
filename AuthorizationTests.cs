using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.DTOs;
using SafeVault.Models;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// End-to-end checks that role-based access control is actually enforced
/// by the running pipeline, not just present in attributes.
/// </summary>
public class AuthorizationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public AuthorizationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
        });
    }

    private async Task<(string token, string userId)> RegisterAndLoginAsync(HttpClient client, string userName, string password = "Str0ng!Passw0rd")
    {
        var register = await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest
        {
            UserName = userName,
            Email = $"{userName}@example.com",
            Password = password,
            DisplayName = userName
        });
        register.EnsureSuccessStatusCode();

        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            UserName = userName,
            Password = password
        });
        login.EnsureSuccessStatusCode();

        var body = await login.Content.ReadFromJsonAsync<LoginResponse>();
        return (body!.token, userName);
    }

    private record LoginResponse(string token, string[] roles);

    [Fact]
    public async Task AdminEndpoint_WithoutToken_Returns401()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/users");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AdminEndpoint_WithRegularUserToken_Returns403()
    {
        var client = _factory.CreateClient();
        var (token, _) = await RegisterAndLoginAsync(client, "regularuser1");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await client.GetAsync("/api/users");

        // A logged-in "User"-role account must still be denied an Admin-only route.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AdminEndpoint_WithAdminToken_Succeeds()
    {
        var client = _factory.CreateClient();
        var (_, userName) = await RegisterAndLoginAsync(client, "willbeadmin1");

        // Promote the user to Admin directly via Identity APIs (simulating
        // what an existing admin would do through the assign-role endpoint),
        // then log in again to get a token that carries the new role claim.
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new IdentityRole("Admin"));
            }
            var user = await userManager.FindByNameAsync(userName);
            await userManager.AddToRoleAsync(user!, "Admin");
        }

        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            UserName = userName,
            Password = "Str0ng!Passw0rd"
        });
        var body = await login.Content.ReadFromJsonAsync<LoginResponse>();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body!.token);
        var response = await client.GetAsync("/api/users");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task User_CannotDeleteAnotherUsersVaultItem()
    {
        var clientA = _factory.CreateClient();
        var (tokenA, _) = await RegisterAndLoginAsync(clientA, "ownerA1");
        clientA.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenA);

        var create = await clientA.PostAsJsonAsync("/api/vault", new VaultItemRequest
        {
            Title = "Owner A secret",
            Notes = "only for A"
        });
        create.EnsureSuccessStatusCode();
        var created = await create.Content.ReadFromJsonAsync<VaultItemDto>();

        var clientB = _factory.CreateClient();
        var (tokenB, _) = await RegisterAndLoginAsync(clientB, "attackerB1");
        clientB.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenB);

        // Attacker B tries to delete Owner A's item by guessing/incrementing the id (IDOR attempt).
        var delete = await clientB.DeleteAsync($"/api/vault/{created!.Id}");

        Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
    }

    private record VaultItemDto(int Id, string Title, string Notes, string OwnerUserId);
}
