using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<Dictionary<string, int>>();

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentByIdAsync)
            .WithTags("Incidents")
            .RequireAuthorization()
            .WithName("GetIncidentComment")
            .Produces<IncidentCommentResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out var userId, out var isAnalyst))
            return Results.Unauthorized();

        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        var items = await queries.GetListAsync(parsedStatus, userId, isAnalyst, cancellationToken);
        return Results.Ok(items);
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        IncidentQueries queries,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out var userId, out var isAnalyst))
            return Results.Unauthorized();

        var incidentEntity = await queries.FindEntityByIdAsync(id, cancellationToken);
        if (incidentEntity is null)
            return IncidentNotFound(id);

        var decision = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incidentEntity,
            IncidentOperations.Read);

        if (!decision.Succeeded)
            return IncidentNotFound(id);

        var incident = await queries.GetDetailsAsync(id, userId, isAnalyst, cancellationToken);
        return incident is null ? IncidentNotFound(id) : Results.Ok(incident);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        SecureLabDbContext db,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out _, out _))
            return Results.Unauthorized();

        var entity = await db.Incidents.FirstOrDefaultAsync(i => i.Id == id, cancellationToken);
        if (entity is null)
            return IncidentNotFound(id);

        var decision = await authorizationService.AuthorizeAsync(
            httpContext.User,
            entity,
            IncidentOperations.Update);

        if (!decision.Succeeded)
            return IncidentNotFound(id);

        if (string.IsNullOrWhiteSpace(request.Title) || request.Title.Trim().Length < 5)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["title"] = ["Заголовок має містити щонайменше 5 символів."]
            });
        }

        if (string.IsNullOrWhiteSpace(request.Description) || request.Description.Trim().Length < 20)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["description"] = ["Опис має містити щонайменше 20 символів."]
            });
        }

        if (!Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
            || !Enum.IsDefined(severity))
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["severity"] = ["Некоректний рівень критичності."]
            });
        }

        entity.Title = request.Title.Trim();
        entity.Description = request.Description.Trim();
        entity.Severity = severity;
        entity.UpdatedAtUtc = DateTimeOffset.UtcNow;

        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        SecureLabDbContext db,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out var userId, out var isAnalyst))
            return Results.Unauthorized();

        var entity = await db.Incidents.FirstOrDefaultAsync(i => i.Id == id, cancellationToken);
        if (entity is null)
            return IncidentNotFound(id);

        if (!isAnalyst)
        {
            var auditLogger = loggerFactory.CreateLogger("SecurityAudit");
            auditLogger.LogWarning(
                "SecurityAudit: Denied privileged transition Triage on incident {IncidentId} for user {UserId}",
                id,
                userId);

            return Results.Problem(
                title: "Недостатньо прав",
                detail: "Тільки аналітик може виконувати triage інциденту.",
                statusCode: StatusCodes.Status403Forbidden);
        }

        if (entity.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Некоректний перехід стану",
                detail: $"Неможливо виконати triage для інциденту у стані '{entity.Status}'.",
                statusCode: StatusCodes.Status409Conflict);
        }

        var decision = await authorizationService.AuthorizeAsync(
            httpContext.User,
            entity,
            IncidentOperations.Triage);

        if (!decision.Succeeded)
            return Results.Forbid();

        entity.Status = IncidentStatus.Triaged;
        entity.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);

        return Results.NoContent();
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        SecureLabDbContext db,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out var userId, out var isAnalyst))
            return Results.Unauthorized();

        var query = db.Incidents.AsNoTracking();
        if (!isAnalyst)
        {
            query = query.Where(i => i.OwnerUserId == userId);
        }

        var grouped = await query
            .GroupBy(i => i.Severity)
            .Select(g => new { Severity = g.Key.ToString(), Count = g.Count() })
            .ToDictionaryAsync(x => x.Severity, x => x.Count, cancellationToken);

        return Results.Ok(grouped);
    }

    private static async Task<IResult> GetCommentByIdAsync(
        Guid id,
        SecureLabDbContext db,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out var userId, out var isAnalyst))
            return Results.Unauthorized();

        var comment = await db.IncidentComments
            .AsNoTracking()
            .Include(c => c.Incident)
            .Include(c => c.Author)
            .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);

        if (comment is null)
            return Results.NotFound();

        if (!isAnalyst && (comment.IsInternal || comment.Incident.OwnerUserId != userId))
            return Results.NotFound();

        return Results.Ok(new IncidentCommentResponse(
            comment.Id,
            comment.Author.DisplayName,
            comment.Text,
            comment.CreatedAtUtc));
    }

    private static bool TryGetUserContext(HttpContext httpContext, out Guid userId, out bool isAnalyst)
    {
        isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var userIdStr = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(userIdStr, out userId);
    }

    private static IResult IncidentNotFound(Guid id) => Results.Problem(
        title: "Інцидент не знайдено",
        detail: $"Інцидент '{id}' не існує.",
        statusCode: StatusCodes.Status404NotFound);
}