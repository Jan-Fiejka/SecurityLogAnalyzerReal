namespace SecurityLogAnalyzer.Api;

public sealed record AnalysisResult(
    int TotalAttempts,
    int SuccessfulLogins,
    int FailedLogins,
    int SuspiciousUsers,
    int SuspiciousIps,
    IReadOnlyList<SuspiciousPattern> Patterns);

public sealed record SuspiciousPattern(
    string Rule,
    string Subject,
    int EventCount,
    DateTime FirstAttemptUtc,
    DateTime LastAttemptUtc,
    string Reason,
    string Severity);

public static class SecurityAnalyzer
{
    public static AnalysisResult Analyze(IReadOnlyList<LoginEvent> events)
    {
        var failures = events.Where(entry => !entry.Succeeded).OrderBy(entry => entry.OccurredAtUtc).ToList();
        var patterns = new List<SuspiciousPattern>();

        foreach (var group in failures.GroupBy(entry => entry.Username))
        {
            var ordered = group.ToList();
            if (ordered.Count >= 3)
            {
                patterns.Add(CreatePattern("UserFailureCount", group.Key, ordered,
                    "Mindestens 3 fehlgeschlagene Login-Versuche für diesen Benutzer", "medium"));
            }

            AddBurstPattern(patterns, "UserBruteForce", group.Key, ordered, 5, TimeSpan.FromMinutes(10),
                "Mindestens 5 Fehlversuche für diesen Benutzer innerhalb von 10 Minuten", "high");
        }

        foreach (var group in failures.GroupBy(entry => entry.IpAddress))
        {
            var ordered = group.ToList();
            AddBurstPattern(patterns, "IpBruteForce", group.Key, ordered, 5, TimeSpan.FromMinutes(10),
                "Mindestens 5 Fehlversuche von dieser IP innerhalb von 10 Minuten", "high");

            var usernames = ordered.Select(entry => entry.Username).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (usernames.Count >= 3)
            {
                patterns.Add(CreatePattern("IpUserSpray", group.Key, ordered,
                    $"Diese IP-Adresse hat {usernames.Count} verschiedene Benutzer angegriffen", "high"));
            }
        }

        foreach (var success in events.Where(entry => entry.Succeeded))
        {
            var precedingFailures = failures.Count(entry =>
                entry.Username.Equals(success.Username, StringComparison.OrdinalIgnoreCase) &&
                entry.IpAddress == success.IpAddress &&
                entry.OccurredAtUtc <= success.OccurredAtUtc &&
                success.OccurredAtUtc - entry.OccurredAtUtc <= TimeSpan.FromMinutes(10));

            if (precedingFailures >= 3)
            {
                patterns.Add(new SuspiciousPattern("SuccessAfterFailures", success.Username, precedingFailures,
                    success.OccurredAtUtc.AddMinutes(-10), success.OccurredAtUtc,
                    "Erfolgreicher Login nach mindestens 3 Fehlversuchen von derselben IP", "high"));
            }
        }

        var suspiciousUsers = patterns.Where(pattern => pattern.Rule.StartsWith("User", StringComparison.Ordinal) || pattern.Rule == "SuccessAfterFailures")
            .Select(pattern => pattern.Subject).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var suspiciousIps = patterns.Where(pattern => pattern.Rule.StartsWith("Ip", StringComparison.Ordinal))
            .Select(pattern => pattern.Subject).Distinct(StringComparer.OrdinalIgnoreCase).Count();

        return new AnalysisResult(events.Count, events.Count(entry => entry.Succeeded), failures.Count,
            suspiciousUsers, suspiciousIps, patterns.OrderByDescending(pattern => pattern.Severity).ThenByDescending(pattern => pattern.EventCount).ToList());
    }

    private static void AddBurstPattern(List<SuspiciousPattern> patterns, string rule, string subject,
        List<LoginEvent> events, int minimumCount, TimeSpan window, string reason, string severity)
    {
        for (var start = 0; start <= events.Count - minimumCount; start++)
        {
            var end = start + minimumCount - 1;
            if (events[end].OccurredAtUtc - events[start].OccurredAtUtc <= window)
            {
                patterns.Add(new SuspiciousPattern(rule, subject, end - start + 1,
                    events[start].OccurredAtUtc, events[end].OccurredAtUtc, reason, severity));
                return;
            }
        }
    }

    private static SuspiciousPattern CreatePattern(string rule, string subject, List<LoginEvent> events, string reason, string severity)
        => new(rule, subject, events.Count, events[0].OccurredAtUtc, events[^1].OccurredAtUtc, reason, severity);
}