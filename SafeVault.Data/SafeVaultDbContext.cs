using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Models;

namespace SafeVault.Data;

public class SafeVaultDbContext : DbContext
{
    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();
    public DbSet<VaultItem> VaultItems => Set<VaultItem>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User Configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(u => u.Id);
            entity.HasIndex(u => u.Username).IsUnique();
            entity.HasIndex(u => u.Email).IsUnique();
            entity.Property(u => u.Username).IsRequired().HasMaxLength(50);
            entity.Property(u => u.Email).IsRequired().HasMaxLength(100);
            entity.Property(u => u.PasswordHash).IsRequired();
            entity.Property(u => u.Role).IsRequired().HasMaxLength(20);
        });

        // VaultItem Configuration
        modelBuilder.Entity<VaultItem>(entity =>
        {
            entity.HasKey(v => v.Id);
            entity.Property(v => v.Title).IsRequired().HasMaxLength(100);
            entity.Property(v => v.Content).IsRequired().HasMaxLength(5000);
            entity.Property(v => v.Category).IsRequired().HasMaxLength(50);

            entity.HasOne(v => v.User)
                  .WithMany(u => u.VaultItems)
                  .HasForeignKey(v => v.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
