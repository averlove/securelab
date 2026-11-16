using System.Net;
using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

public sealed class SearchMechanicsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Search_ReturnsJson()
    {
        using var client = factory.CreateClient();
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password") ?? "Pa$$w0rD$ecure1";
        var login = await client.PostAsJsonAsync("/api/auth/login", new { userName = "morgan", password });
        login.EnsureSuccessStatusCode();

        using var response = await client.GetAsync("/api/incidents/search?q=навчальн");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }
}