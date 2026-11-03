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
}