using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data;

// Using EF Core (parameterized under the hood) instead of hand-built SQL
// strings is the primary SQL-injection defense for this app. Anywhere we
// still need raw SQL (see UsersRepository) we use parameters explicitly.
public class SafeVaultDbContext : IdentityDbContext<ApplicationUser>
{
    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options)
        : base(options)
    {
    }

    public DbSet<VaultItem> VaultItems => Set<VaultItem>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<VaultItem>()
            .HasIndex(v => v.OwnerUserId);
    }
}
