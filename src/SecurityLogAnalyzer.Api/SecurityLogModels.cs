using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace SecurityLogAnalyzer.Api;

public sealed class SecurityLogDbContext(DbContextOptions<SecurityLogDbContext> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<LoginEvent> LoginEvents => Set<LoginEvent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AppUser>().HasIndex(user => user.Username).IsUnique();
        modelBuilder.Entity<LoginEvent>().HasIndex(entry => entry.OccurredAtUtc);
        modelBuilder.Entity<LoginEvent>().HasIndex(entry => new { entry.Username, entry.Succeeded });
    }
}

public sealed class AppUser
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string PasswordHash { get; set; } = "";
}

public sealed class LoginEvent
{
    public long Id { get; set; }
    public string Username { get; set; } = "";
    public bool Succeeded { get; set; }
    public string? FailureReason { get; set; }
    public string IpAddress { get; set; } = "";
    public string UserAgent { get; set; } = "";
    public DateTime OccurredAtUtc { get; set; }
}

public sealed record LoginRequest(string Username, string Password);

public static class PasswordHasher
{
    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(password, salt, 120_000, HashAlgorithmName.SHA256, 32);
        return $"v1.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(derivedKey)}";
    }

    public static bool Verify(string password, string storedHash)
    {
        var parts = storedHash.Split('.');
        if (parts.Length != 3 || parts[0] != "v1") return false;
        try
        {
            var salt = Convert.FromBase64String(parts[1]);
            var expected = Convert.FromBase64String(parts[2]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, 120_000, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

public static class SeedData
{
    public static void Initialize(SecurityLogDbContext database)
    {
        if (database.Users.Any()) return;
        database.Users.AddRange(
            new AppUser { Username = "anna", PasswordHash = PasswordHasher.Hash("test1") },
            new AppUser { Username = "ben", PasswordHash = PasswordHasher.Hash("test2") },
            new AppUser { Username = "cara", PasswordHash = PasswordHasher.Hash("test3") });
        database.SaveChanges();
    }
}