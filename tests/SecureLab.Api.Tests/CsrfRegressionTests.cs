using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class CsrfRegressionTests : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid AliceIncident1Id = Guid.Parse("20000000-0000-0000-0000-000000000001");
    private readonly SecureLabApiFactory _factory;

    public CsrfRegressionTests(SecureLabApiFactory factory)
    {
        _factory = factory;
    }

    // REG-CSRF-01: Login -> reject without CSRF token -> state unchanged -> issue token -> valid update -> state updated
    [Fact]
    public async Task Csrf_WithoutToken_IsRejected_StateUnchanged_ThenValidPairSucceeds()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password") ?? "Pa$$w0rD$ecure1";
        using var client = await _factory.LoginAsync("alice", password);

        // 1. Read initial resource state (before)
        var before = await client.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{AliceIncident1Id}");
        Assert.NotNull(before);

        // 2. Mutating request WITHOUT X-SecureLab-CSRF header -> 400 Bad Request
        var rejectedResponse = await client.PutAsJsonAsync($"/api/incidents/{AliceIncident1Id}", new
        {
            title = "Rejected CSRF Title Update",
            description = "Description that must not be saved without CSRF token.",
            severity = "High"
        });
        Assert.Equal(HttpStatusCode.BadRequest, rejectedResponse.StatusCode);

        var problem = await rejectedResponse.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("Antiforgery token is missing or invalid.", problem.Title);

        // 3. Verify state in DB did not change (state == before)
        var afterReject = await client.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{AliceIncident1Id}");
        Assert.NotNull(afterReject);
        Assert.Equal(before.Title, afterReject.Title);
        Assert.Equal(before.Description, afterReject.Description);
        Assert.Equal(before.Severity, afterReject.Severity);

        // 4. Fetch CSRF token with the same client and send X-SecureLab-CSRF header
        var tokenResponse = await client.GetFromJsonAsync<CsrfTokenResponse>("/api/csrf-token");
        Assert.NotNull(tokenResponse);
        Assert.False(string.IsNullOrWhiteSpace(tokenResponse.Token));

        var expectedTitle = $"Updated With Valid CSRF {Guid.NewGuid():N}";
        var expectedDescription = "Valid description updated with matching CSRF cookie and header.";
        var expectedSeverity = "High";

        using var validRequest = new HttpRequestMessage(HttpMethod.Put, $"/api/incidents/{AliceIncident1Id}")
        {
            Content = JsonContent.Create(new
            {
                title = expectedTitle,
                description = expectedDescription,
                severity = expectedSeverity
            })
        };
        validRequest.Headers.Add("X-SecureLab-CSRF", tokenResponse.Token);

        var validResponse = await client.SendAsync(validRequest);
        Assert.Equal(HttpStatusCode.NoContent, validResponse.StatusCode);

        // 5. Verify state updated as expected
        var afterSuccess = await client.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{AliceIncident1Id}");
        Assert.NotNull(afterSuccess);
        Assert.Equal(expectedTitle, afterSuccess.Title);
        Assert.Equal(expectedDescription, afterSuccess.Description);
        Assert.Equal(expectedSeverity, afterSuccess.Severity);
    }

    private sealed record CsrfTokenResponse(string Token);
}