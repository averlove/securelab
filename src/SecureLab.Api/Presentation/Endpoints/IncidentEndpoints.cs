using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
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
            .RequireAuthorization(); // Вимога ЛР 04: Всі ендпоінти інцидентів вимагають авторизації

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", () => Results.Problem(
                title: "Точку розширення ще не реалізовано",
                detail: "Завершіть цей endpoint під час лабораторної роботи № 1.",
                statusCode: StatusCodes.Status501NotImplemented))
            .WithName("GetIncidentSeveritySummary")
            .ProducesProblem(StatusCodes.Status501NotImplemented);

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var userIdStr = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdStr, out var userId))
        {
            return Results.Unauthorized();
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);

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
        var userIdStr = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdStr, out var userId))
        {
            return Results.Unauthorized();
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);

        // 1. Завантажуємо базову сутність для перевірки через IncidentAuthorizationHandler
        var incidentEntity = await queries.FindEntityByIdAsync(id, cancellationToken);
        if (incidentEntity is null)
        {
            return IncidentNotFound(id);
        }

        // 2. Викликаємо централізований Handler
        var decision = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incidentEntity,
            IncidentOperations.Read);

        if (!decision.Succeeded)
        {
            // Політика 404: чужий інцидент виглядає для клієнта так само, як неіснуючий
            return IncidentNotFound(id);
        }

        // 3. Якщо доступ дозволено — отримуємо повні деталі
        var incident = await queries.GetDetailsAsync(id, userId, isAnalyst, cancellationToken);
        return incident is null ? IncidentNotFound(id) : Results.Ok(incident);
    }

    private static IResult IncidentNotFound(Guid id) => Results.Problem(
        title: "Інцидент не знайдено",
        detail: $"Інцидент '{id}' не існує.",
        statusCode: StatusCodes.Status404NotFound);
}