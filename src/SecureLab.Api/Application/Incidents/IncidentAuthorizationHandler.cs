using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// Определяем операции, которые требуют проверки прав (согласно Матрице доступа)
public static class IncidentOperations
{
    public static readonly OperationAuthorizationRequirement Read = new() { Name = nameof(Read) };
    public static readonly OperationAuthorizationRequirement Triage = new() { Name = nameof(Triage) };
}

// Централизованный обработчик авторизации для ресурса Incident
public sealed class IncidentAuthorizationHandler : AuthorizationHandler<OperationAuthorizationRequirement, Incident>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Incident incident)
    {
        // 1. Извлекаем ID текущего пользователя из токена/cookie
        var userIdValue = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var isOwner = Guid.TryParse(userIdValue, out var userId) && userId == incident.OwnerUserId;
        
        // 2. Проверяем, есть ли у пользователя роль Аналитика (Analyst)
        var isAnalyst = context.User.IsInRole(DbSeeder.AnalystRole);

        // 3. Логика матрицы доступа для конкретных действий
        bool allowed = requirement.Name switch
        {
            // Просмотр деталей: разрешено владельцу ресурса ИЛИ Аналитику
            nameof(IncidentOperations.Read) => isOwner || isAnalyst,
            
            // Смена статуса (Triage): разрешено ТОЛЬКО Аналитику и ТОЛЬКО если статус "New"
            nameof(IncidentOperations.Triage) => isAnalyst && incident.Status == IncidentStatus.New,
            
            _ => false
        };

        // 4. Если действие разрешено, сообщаем об успехе
        if (allowed)
        {
            context.Succeed(requirement);
        }

        // Если не разрешено, Task.CompletedTask вернется без вызова Succeed, что приведет к 403 или 404
        return Task.CompletedTask;
    }
}