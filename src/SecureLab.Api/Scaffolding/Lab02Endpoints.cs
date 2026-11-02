using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Security.Claims;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var pattern = "%" + EscapeLike(q ?? "") + "%";

            var query = db.Incidents.AsNoTracking()
                .Where(x => EF.Functions.ILike(x.Title, pattern, "\\") 
                         || EF.Functions.ILike(x.Description, pattern, "\\"));

            IQueryable<Incident>? orderedQuery = sortBy switch
            {
                null or "" or "createdAtUtc" => query
                    .OrderByDescending(x => x.CreatedAtUtc)
                    .ThenBy(x => x.Id),

                "severity" => query
                    .OrderBy(x => x.Severity == IncidentSeverity.Critical ? 0
                                : x.Severity == IncidentSeverity.High ? 1
                                : x.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(x => x.Id),

                "status" => query
                    .OrderBy(x => x.Status == IncidentStatus.New ? 0
                                : x.Status == IncidentStatus.Triaged ? 1
                                : x.Status == IncidentStatus.InProgress ? 2
                                : x.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(x => x.Id),

                _ => null
            };

            if (orderedQuery is null)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });
            }

            var items = await orderedQuery
                .Take(50)
                .Select(x => new IncidentSearchResponse(
                    x.Id,
                    x.Title,
                    x.Description,
                    x.Severity.ToString(),
                    x.Status.ToString(),
                    x.CreatedAtUtc))
                .ToListAsync(ct);

            return Results.Ok(items);
        });

        app.MapPost("/api/incidents", async (
    CreateIncidentRequest request, 
    SecureLabDbContext db, 
    ClaimsPrincipal userPrincipal, 
    CancellationToken ct) =>
{
    // ЛР 03 (А-05): Отримуємо ідентифікатор авторизованого користувача з principal
    var userIdStr = userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!Guid.TryParse(userIdStr, out var verifiedUserId))
    {
        return Results.Unauthorized();
    }

    var now = DateTimeOffset.UtcNow;
    var errors = new Dictionary<string, string[]>();

    if (string.IsNullOrWhiteSpace(request.Title))
    {
        errors["title"] = ["Заголовок обов'язковий."];
    }
    else if (request.Title.Length > 160)
    {
        errors["title"] = ["Заголовок не повинен перевищувати 160 символів."];
    }

    if (string.IsNullOrWhiteSpace(request.Description))
    {
        errors["description"] = ["Опис обов'язковий."];
    }
    else if (request.Description.Length > 4000)
    {
        errors["description"] = ["Опис не повинен перевищувати 4000 символів."];
    }

    var severityIsValid = Enum.TryParse<IncidentSeverity>(request.Severity, true, out var severity) 
                          && Enum.IsDefined(severity);
    if (!severityIsValid)
    {
        errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];
    }

    if (request.OccurredAtUtc is null)
    {
        errors["occurredAtUtc"] = ["Час виникнення обов'язковий."];
    }
    else if (request.OccurredAtUtc > now.AddMinutes(5))
    {
        errors["occurredAtUtc"] = ["Час виникнення не може бути в майбутньому."];
    }

    var normalizedTitle = request.Title?.Trim() ?? "";
    var normalizedDescription = request.Description?.Trim() ?? "";

    if (severityIsValid && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical))
    {
        if (!errors.ContainsKey("description") && normalizedDescription.Length < 40)
        {
            errors["description"] = ["Для критичних інцидентів (High/Critical) опис має містити щонайменше 40 символів."];
        }
    }

    if (!errors.ContainsKey("description") && normalizedTitle.Length > 0 && 
        string.Equals(normalizedTitle, normalizedDescription, StringComparison.OrdinalIgnoreCase))
    {
        errors["description"] = ["Опис не повинен повторювати заголовок інциденту."];
    }

    if (errors.Count > 0)
    {
        return Results.ValidationProblem(errors);
    }

    var activeStatuses = new[] { IncidentStatus.New, IncidentStatus.Triaged, IncidentStatus.InProgress, IncidentStatus.Resolved };
    var hasConflict = await db.Incidents.AnyAsync(x => 
        x.Title == normalizedTitle && activeStatuses.Contains(x.Status), ct);

    if (hasConflict)
    {
        return Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "Дублікат інциденту",
            detail: "Активний інцидент із таким заголовком уже існує.");
    }

    var incident = new Incident
    {
        Id = Guid.NewGuid(),
        OwnerUserId = verifiedUserId, // ЛР 03: Власник встановлюється виключно з verified principal
        Title = normalizedTitle,
        Description = normalizedDescription,
        Severity = severity,
        Status = IncidentStatus.New,
        OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
        CreatedAtUtc = now,
        UpdatedAtUtc = now
    };

    db.Incidents.Add(incident);
    await db.SaveChangesAsync(ct);

    var response = new CreatedIncidentResponse(
        incident.Id,
        incident.Title,
        incident.Description,
        incident.Severity.ToString(),
        incident.Status.ToString(),
        incident.OccurredAtUtc,
        incident.CreatedAtUtc
    );

    return Results.Created($"/api/incidents/{incident.Id}", response);
}).RequireAuthorization(); // ЛР 03 (А-04): Обов'язкова авторизація
    }

    private static string EscapeLike(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("%", "\\%")
            .Replace("_", "\\_");
    }
}

public sealed record CreateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);

public sealed record IncidentSearchResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset CreatedAtUtc);