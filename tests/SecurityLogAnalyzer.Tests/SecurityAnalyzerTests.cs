using SecurityLogAnalyzer.Api;

namespace SecurityLogAnalyzer.Tests;

public class SecurityAnalyzerTests
{
    [Fact]
    public void PasswordHash_RoundTrips_AndRejectsWrongPassword()
    {
        var hash = PasswordHasher.Hash("secret");

        Assert.True(PasswordHasher.Verify("secret", hash));
        Assert.False(PasswordHasher.Verify("wrong", hash));
    }

    [Fact]
    public void Analyze_FindsUserWithThreeFailedAttempts()
    {
        var start = DateTime.UtcNow;
        var events = Enumerable.Range(0, 5).Select(index => new LoginEvent
        {
            Username = "unknown",
            Succeeded = index == 4,
            OccurredAtUtc = start.AddMinutes(index)
        }).ToList();

        var result = SecurityAnalyzer.Analyze(events);

        Assert.Equal(5, result.TotalAttempts);
        Assert.Equal(4, result.FailedLogins);
        Assert.Contains(result.Patterns, pattern => pattern.Rule == "UserFailureCount" && pattern.Subject == "unknown");
        Assert.Contains(result.Patterns, pattern => pattern.Rule == "SuccessAfterFailures" && pattern.Subject == "unknown");
    }

    [Fact]
    public void Analyze_FindsIpBruteForceAndUserSpraying()
    {
        var start = DateTime.UtcNow;
        var events = new[] { "anna", "ben", "cara", "dora", "erik" }.Select((username, index) => new LoginEvent
        {
            Username = username,
            IpAddress = "203.0.113.10",
            Succeeded = false,
            OccurredAtUtc = start.AddMinutes(index)
        }).ToList();

        var result = SecurityAnalyzer.Analyze(events);

        Assert.Equal(1, result.SuspiciousIps);
        Assert.Contains(result.Patterns, pattern => pattern.Rule == "IpBruteForce");
        Assert.Contains(result.Patterns, pattern => pattern.Rule == "IpUserSpray");
    }
}