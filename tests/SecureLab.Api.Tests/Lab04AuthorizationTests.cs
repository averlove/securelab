using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using Microsoft.AspNetCore.Hosting;

namespace SecureLab.Api.Tests;

public sealed class Lab04AuthorizationTests : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid AliceIncident1Id = Guid.Parse("20000000-0000-0000-0000-000000000001");
    private static readonly Guid BobIncident2Id = Guid.Parse("20000000-0000-0000-0000-000000000002");
    private static readonly Guid BobIncident4Id = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private static readonly Guid AliceIncident5Id = Guid.Parse("20000000-0000-0000-0000-000000000005");
    private static readonly Guid InternalComment3Id = Guid.Parse("30000000-0000-0000-0000-000000000003");

    private readonly SecureLabApiFactory _factory;

    public Lab04AuthorizationTests(SecureLabApiFactory factory)
    {
        _factory = factory;
    }

    // A-01: Анонімний запит на захищений ресурс повертає 401 Unauthorized
    [Fact]
    public async Task A01_Anonymous_AccessToIncidents_Returns401()
    {
        using var client = _factory.CreateClient();

        var listResponse = await client.GetAsync("/api/incidents");
        var itemResponse = await client.GetAsync($"/api/incidents/{AliceIncident1Id}");

        Assert.Equal(HttpStatusCode.Unauthorized, listResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, itemResponse.StatusCode);
    }

    // A-02: Власник (alice) має доступ до власного інциденту (200 OK)
    [Fact]
    public async Task A02_Owner_CanReadOwnIncident_Returns200()
    {
        using var alice = await LoginAsAsync("alice");

        var response = await alice.GetAsync($"/api/incidents/{AliceIncident1Id}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var details = await response.Content.ReadFromJsonAsync<IncidentDetailsResponse>();
        Assert.NotNull(details);
        Assert.Equal(AliceIncident1Id, details.Id);
    }

    // A-03: Інший Reporter (alice) не бачить чужий інцидент (bob) -> 404 Not Found
    [Fact]
    public async Task A03_NonOwnerReporter_CannotReadOtherIncident_Returns404()
    {
        using var alice = await LoginAsAsync("alice");

        var response = await alice.GetAsync($"/api/incidents/{BobIncident2Id}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // A-03R: Analyst (morgan) бачить інциденти будь-якого користувача -> 200 OK
    [Fact]
    public async Task A03R_Analyst_CanReadAnyIncident_Returns200()
    {
        using var morgan = await LoginAsAsync("morgan");

        var response = await morgan.GetAsync($"/api/incidents/{BobIncident2Id}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var details = await response.Content.ReadFromJsonAsync<IncidentDetailsResponse>();
        Assert.NotNull(details);
        Assert.Equal(BobIncident2Id, details.Id);
    }

    // A-04: Чужий користувач не може змінити чужий інцидент; стан у БД не змінюється
    [Fact]
    public async Task A04_OtherReporter_CannotMutateOtherIncident_DbUnchanged()
    {
        using var alice = await LoginAsAsync("alice");
        await AddCsrfHeaderAsync(alice);

        string originalTitle;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            originalTitle = (await db.Incidents.AsNoTracking().SingleAsync(i => i.Id == BobIncident2Id)).Title;
        }

        var response = await alice.PutAsJsonAsync($"/api/incidents/{BobIncident2Id}", new
        {
            title = "Hacked by Alice",
            description = "Unauthorized modification attempt",
            severity = "Critical"
        });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var afterTitle = (await db.Incidents.AsNoTracking().SingleAsync(i => i.Id == BobIncident2Id)).Title;
            Assert.Equal(originalTitle, afterTitle);
        }
    }

    // A-05: Список GET /api/incidents повертає тільки дозволені ресурси
    [Fact]
    public async Task A05_ListIncidents_ScopedByRoleAndOwnership()
    {
        using var alice = await LoginAsAsync("alice");
        using var morgan = await LoginAsAsync("morgan");

        var aliceItems = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        var morganItems = await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(aliceItems);
        Assert.NotNull(morganItems);

        Assert.Contains(aliceItems, i => i.Id == AliceIncident1Id);
        Assert.Contains(aliceItems, i => i.Id == AliceIncident5Id);
        Assert.DoesNotContain(aliceItems, i => i.Id == BobIncident2Id);
        Assert.DoesNotContain(aliceItems, i => i.Id == BobIncident4Id);

        Assert.Contains(morganItems, i => i.Id == AliceIncident1Id);
        Assert.Contains(morganItems, i => i.Id == BobIncident2Id);
    }

    // A-06: Reporter не може виконати привілейовану операцію triage -> 403 Forbidden
    [Fact]
    public async Task A06_Reporter_CannotTriageOwnIncident_Returns403()
    {
        using var alice = await LoginAsAsync("alice");
        await AddCsrfHeaderAsync(alice);

        var response = await alice.PostAsync($"/api/incidents/{AliceIncident1Id}/triage", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // A-07: Analyst може виконати triage (New -> Triaged), повторний виклик -> 409 Conflict
    [Fact]
    public async Task A07_Analyst_CanTriageNewIncident_AndRejectsInvalidTransition()
    {
        using var morgan = await LoginAsAsync("morgan");
        await AddCsrfHeaderAsync(morgan);

        // Створюємо свіжий інцидент у стані New для ізольованої перевірки переходу
        var createResp = await morgan.PostAsJsonAsync("/api/incidents", new
        {
            title = $"Triage test incident {Guid.NewGuid():N}",
            description = "Detailed description exceeding forty characters for validation.",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        createResp.EnsureSuccessStatusCode();
        var created = await createResp.Content.ReadFromJsonAsync<JsonElement>();
        var newId = created.GetProperty("id").GetGuid();

        var triageResp = await morgan.PostAsync($"/api/incidents/{newId}/triage", content: null);
        Assert.Equal(HttpStatusCode.NoContent, triageResp.StatusCode);

        var secondTriageResp = await morgan.PostAsync($"/api/incidents/{newId}/triage", content: null);
        Assert.Equal(HttpStatusCode.Conflict, secondTriageResp.StatusCode);
    }

    // A-08: Захист server-managed полів (OwnerUserId, Status) при створенні та оновленні
    [Fact]
    public async Task A08_ServerManagedFields_CannotBeSpoofedByClient()
    {
        using var alice = await LoginAsAsync("alice");
        await AddCsrfHeaderAsync(alice);

        // A-08a: Спроба підмінити ownerUserId на BobId і status на Closed при POST
        var createResp = await alice.PostAsJsonAsync("/api/incidents", new
        {
            title = $"Spoof owner test {Guid.NewGuid():N}",
            description = "Testing that ownerUserId and status cannot be overridden by client payload.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5),
            ownerUserId = DbSeeder.BobId,
            status = "Closed"
        });
        createResp.EnsureSuccessStatusCode();
        var created = await createResp.Content.ReadFromJsonAsync<JsonElement>();
        var createdId = created.GetProperty("id").GetGuid();
        Assert.Equal("New", created.GetProperty("status").GetString());

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var entity = await db.Incidents.AsNoTracking().SingleAsync(i => i.Id == createdId);
            Assert.Equal(DbSeeder.AliceId, entity.OwnerUserId);
            Assert.Equal(IncidentStatus.New, entity.Status);
        }

        // A-08b: Спроба змінити status або ownerUserId через PUT
        var updateResp = await alice.PutAsJsonAsync($"/api/incidents/{createdId}", new
        {
            title = "Updated clean title",
            description = "Updated clean description with sufficient length.",
            severity = "Medium",
            status = "Closed",
            ownerUserId = DbSeeder.BobId
        });
        Assert.Equal(HttpStatusCode.NoContent, updateResp.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var entity = await db.Incidents.AsNoTracking().SingleAsync(i => i.Id == createdId);
            Assert.Equal(DbSeeder.AliceId, entity.OwnerUserId);
            Assert.Equal(IncidentStatus.New, entity.Status);
        }
    }

    // A-09: Audit log фіксує відмову в привілейованій дії без cookie/паролів/секретів
    [Fact]
    public async Task A09_DeniedPrivilegedAction_WritesSafeAuditEvent()
    {
        var logSink = new List<string>();
        using var customFactory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureLogging(logging =>
            {
                logging.AddProvider(new InMemoryAuditLoggerProvider(logSink));
            });
        });

        using var client = customFactory.CreateClient();
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password") ?? "Pa$$w0rD$ecure1";
        var loginResp = await client.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password });
        loginResp.EnsureSuccessStatusCode();

        await AddCsrfHeaderAsync(client);

        var triageResp = await client.PostAsync($"/api/incidents/{AliceIncident1Id}/triage", content: null);
        Assert.Equal(HttpStatusCode.Forbidden, triageResp.StatusCode);

        var auditEntry = Assert.Single(logSink, line => line.Contains("SecurityAudit: Denied privileged transition"));
        Assert.Contains(AliceIncident1Id.ToString(), auditEntry);
        Assert.Contains(DbSeeder.AliceId.ToString(), auditEntry);
        Assert.DoesNotContain(password, auditEntry);
        Assert.DoesNotContain(".AspNetCore.Identity.Application", auditEntry);
    }

    // A-10: Політика 404 для чужого ресурсу не відрізняється від неіснуючого ID
    [Fact]
    public async Task A10_ForeignResource404_IndistinguishableFromNonExistentId()
    {
        using var alice = await LoginAsAsync("alice");
        var randomId = Guid.NewGuid();

        var foreignResp = await alice.GetAsync($"/api/incidents/{BobIncident2Id}");
        var missingResp = await alice.GetAsync($"/api/incidents/{randomId}");

        Assert.Equal(HttpStatusCode.NotFound, foreignResp.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missingResp.StatusCode);

        var foreignProblem = await foreignResp.Content.ReadFromJsonAsync<ProblemDetails>();
        var missingProblem = await missingResp.Content.ReadFromJsonAsync<ProblemDetails>();

        Assert.NotNull(foreignProblem);
        Assert.NotNull(missingProblem);
        Assert.Equal(foreignProblem.Status, missingProblem.Status);
        Assert.Equal(foreignProblem.Title, missingProblem.Title);
    }

    // A-11: Пошук (/search) та сводка (/severity-summary) не розкривають чужі інциденти
    [Fact]
    public async Task A11_SearchAndSeveritySummary_ScopedToAllowedIncidents()
    {
        using var alice = await LoginAsAsync("alice");
        using var morgan = await LoginAsAsync("morgan");

        // Інцидент №4 ("O'Brien classroom report") належить Bob
        var aliceSearch = await alice.GetFromJsonAsync<List<JsonElement>>("/api/incidents/search?q=Brien");
        var morganSearch = await morgan.GetFromJsonAsync<List<JsonElement>>("/api/incidents/search?q=Brien");

        Assert.NotNull(aliceSearch);
        Assert.Empty(aliceSearch);

        Assert.NotNull(morganSearch);
        Assert.Contains(morganSearch, item => item.GetProperty("id").GetGuid() == BobIncident4Id);

        var aliceSummary = await alice.GetFromJsonAsync<Dictionary<string, int>>("/api/incidents/severity-summary");
        var morganSummary = await morgan.GetFromJsonAsync<Dictionary<string, int>>("/api/incidents/severity-summary");

        Assert.NotNull(aliceSummary);
        Assert.NotNull(morganSummary);
        Assert.True(morganSummary.Values.Sum() > aliceSummary.Values.Sum());
    }

    // A-12: Захист child resource (/api/incident-comments/{id}) та приховування IsInternal
    [Fact]
    public async Task A12_ChildResourceAndInternalComment_ProtectedByRoleAndOwnership()
    {
        using var alice = await LoginAsAsync("alice");
        using var morgan = await LoginAsAsync("morgan");

        // 1. Alice у деталях свого інциденту бачить тільки публічні коментарі (без comment-3)
        var aliceIncident = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{AliceIncident1Id}");
        Assert.NotNull(aliceIncident);
        Assert.DoesNotContain(aliceIncident.Comments, c => c.Id == InternalComment3Id);

        // 2. Morgan бачить internal comment-3 у деталях інциденту
        var morganIncident = await morgan.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{AliceIncident1Id}");
        Assert.NotNull(morganIncident);
        Assert.Contains(morganIncident.Comments, c => c.Id == InternalComment3Id);

        // 3. Прямий запит GET /api/incident-comments/{comment-3} для Alice -> 404, для Morgan -> 200
        var aliceDirectComment = await alice.GetAsync($"/api/incident-comments/{InternalComment3Id}");
        var morganDirectComment = await morgan.GetAsync($"/api/incident-comments/{InternalComment3Id}");

        Assert.Equal(HttpStatusCode.NotFound, aliceDirectComment.StatusCode);
        Assert.Equal(HttpStatusCode.OK, morganDirectComment.StatusCode);
    }

    private async Task<HttpClient> LoginAsAsync(string userName)
    {
        var client = _factory.CreateClient();
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password") ?? "Pa$$w0rD$ecure1";
        var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        response.EnsureSuccessStatusCode();
        return client;
    }

    private static async Task AddCsrfHeaderAsync(HttpClient client)
    {
        using var tokenResponse = await client.GetAsync("/api/csrf-token");
        tokenResponse.EnsureSuccessStatusCode();

        var payload = await tokenResponse.Content.ReadFromJsonAsync<CsrfTokenPayload>();
        if (string.IsNullOrWhiteSpace(payload?.Token))
        {
            throw new InvalidOperationException("CSRF token was not returned by /api/csrf-token.");
        }

        client.DefaultRequestHeaders.Remove("X-SecureLab-CSRF");
        client.DefaultRequestHeaders.Add("X-SecureLab-CSRF", payload.Token);
    }

    private sealed record CsrfTokenPayload(string Token);

    private sealed class InMemoryAuditLoggerProvider(List<string> sink) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new InMemoryLogger(categoryName, sink);
        public void Dispose() { }

        private sealed class InMemoryLogger(string category, List<string> sink) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (category == "SecurityAudit")
                {
                    sink.Add(formatter(state, exception));
                }
            }
        }
    }
}