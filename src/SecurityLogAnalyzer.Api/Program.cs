using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SecurityLogAnalyzer.Api;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<SecurityLogDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("SecurityLog") ?? "Data Source=securitylogs.db"));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "security-analyzer-session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.LoginPath = "/";
    });
builder.Services.AddAuthorization();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var database = scope.ServiceProvider.GetRequiredService<SecurityLogDbContext>();
    database.Database.EnsureCreated();
    SeedData.Initialize(database);
}

app.UseStaticFiles();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/login", async (LoginRequest request, HttpContext httpContext, SecurityLogDbContext database) =>
{
    var username = request.Username.Trim().ToLowerInvariant();
    var user = await database.Users.SingleOrDefaultAsync(candidate => candidate.Username == username);
    var success = user is not null && PasswordHasher.Verify(request.Password, user.PasswordHash);

    database.LoginEvents.Add(new LoginEvent
    {
        Username = username,
        Succeeded = success,
        FailureReason = success ? null : "InvalidCredentials",
        IpAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        UserAgent = httpContext.Request.Headers.UserAgent.ToString(),
        OccurredAtUtc = DateTime.UtcNow
    });
    await database.SaveChangesAsync();

    if (!success)
    {
        return Results.Json(new { message = "Benutzername oder Passwort falsch." }, statusCode: StatusCodes.Status401Unauthorized);
    }

    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
        new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
            new[] { new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, username) },
            CookieAuthenticationDefaults.AuthenticationScheme)));
    return Results.Ok(new { message = "Login erfolgreich." });
});

app.MapGet("/api/logs", async (int? limit, SecurityLogDbContext database) =>
{
    var take = Math.Clamp(limit ?? 100, 1, 1000);
    var logs = await database.LoginEvents.AsNoTracking()
        .OrderByDescending(entry => entry.OccurredAtUtc)
        .Take(take)
        .ToListAsync();
    return Results.Ok(logs);
}).RequireAuthorization();

app.MapGet("/api/analysis", async (SecurityLogDbContext database) =>
{
    var logs = await database.LoginEvents.AsNoTracking().OrderBy(entry => entry.OccurredAtUtc).ToListAsync();
    return Results.Ok(SecurityAnalyzer.Analyze(logs));
}).RequireAuthorization();

app.MapDelete("/api/logs", async (SecurityLogDbContext database) =>
{
    await database.LoginEvents.ExecuteDeleteAsync();
    return Results.NoContent();
}).RequireAuthorization();

app.MapFallbackToFile("index.html");
app.Run();

public partial class Program;
