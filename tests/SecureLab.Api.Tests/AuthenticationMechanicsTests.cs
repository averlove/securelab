using System.Net;
using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationMechanicsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task RealCookie_ReachesSessionCheck()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
        using var client = await factory.LoginAsync("alice", password);
        using var response = await client.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Me_AnonymousAccess_ReturnsUnauthorized()
    {
        using var client = factory.CreateClient();
        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Incidents_AnonymousAccess_ReturnsUnauthorized()
    {
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            Title = "Test Incident",
            Description = "Test Description 1234567890 1234567890 1234567890",
            Severity = "Low",
            OccurredAtUtc = DateTime.UtcNow
        });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Register_ShortPassword_ReturnsBadRequest()
    {
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            Username = "test_user_short",
            Password = "123"
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // REG-AUTH-01: Repeated failed logins lock out account; another user remains unaffected
    [Fact]
    public async Task Login_RepeatedFailures_LocksOutAccount_WithoutAffectingOtherUsers()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

        using var client = factory.CreateClient();

        var targetUser = $"lockout_probe_{Guid.NewGuid():N}";
        using var regResp = await client.PostAsJsonAsync("/api/auth/register", new
        {
            UserName = targetUser,
            Email = $"{targetUser}@example.test",
            DisplayName = "Lockout Probe",
            Password = password
        });
        Assert.Equal(HttpStatusCode.Created, regResp.StatusCode);

        for (var i = 0; i < 5; i++)
        {
            using var failResp = await client.PostAsJsonAsync("/api/auth/login", new
            {
                UserName = targetUser,
                Password = "WrongPassword123!"
            });
            Assert.Equal(HttpStatusCode.Unauthorized, failResp.StatusCode);
        }

        using var lockedResp = await client.PostAsJsonAsync("/api/auth/login", new
        {
            UserName = targetUser,
            Password = password
        });
        Assert.Equal(HttpStatusCode.Unauthorized, lockedResp.StatusCode);

        using var bobClient = await factory.LoginAsync("bob", password);
        using var meResp = await bobClient.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, meResp.StatusCode);
    }
}