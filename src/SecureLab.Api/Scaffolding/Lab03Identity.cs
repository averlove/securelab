using SecureLab.Api.Security;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public record RegisterRequest(
    string UserName,
    string Email,
    string DisplayName,
    string Password);

public record RegisterResponse(
    Guid Id,
    string UserName,
    string DisplayName);

public record LoginRequest(
    string UserName,
    string Password);

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
            options.Lockout.AllowedForNewUsers = true;
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();

        builder.Services.AddAuthorization();

        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;

            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };

            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        // 1. POST /api/auth/register
        app.MapPost("/api/auth/register", async (RegisterRequest input, UserManager<ApplicationUser> userManager) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) ||
                string.IsNullOrWhiteSpace(input.Email) ||
                string.IsNullOrWhiteSpace(input.DisplayName) ||
                string.IsNullOrWhiteSpace(input.Password))
            {
                return Results.BadRequest(new { message = "Усі поля є обов'язковими." });
            }

            if (input.DisplayName.Trim().Length > 120)
            {
                return Results.BadRequest(new { message = "DisplayName не може перевищувати 120 символів." });
            }

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = input.UserName.Trim(),
                Email = input.Email.Trim(),
                DisplayName = input.DisplayName.Trim()
            };

            var result = await userManager.CreateAsync(user, input.Password);
            if (!result.Succeeded)
            {
                var errorCodes = result.Errors.Select(e => e.Code).ToArray();

                if (errorCodes.Contains("DuplicateUserName") || errorCodes.Contains("DuplicateEmail"))
                {
                    return Results.Conflict(new { message = "Користувач з таким іменем або email вже існує.", errors = errorCodes });
                }

                return Results.BadRequest(new { message = "Реєстрація не відповідає вимогам пароля або формату.", errors = errorCodes });
            }

            var roleResult = await userManager.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!roleResult.Succeeded)
            {
                throw new InvalidOperationException("Default role assignment failed.");
            }

            var responseDto = new RegisterResponse(user.Id, user.UserName ?? string.Empty, user.DisplayName);
            return Results.Created("/api/me", responseDto);
        });

        // 2. POST /api/auth/login
        app.MapPost("/api/auth/login", async (LoginRequest input, SignInManager<ApplicationUser> signIn) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, isPersistent: false, lockoutOnFailure: true);
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        });

        // 3. POST /api/auth/logout
        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.NoContent();
        }).RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>();

        // 4. GET /api/me (Verified Principal)
        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();

        // 5. GET /api/auth/session-check
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        var userIdStr = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdStr, out var verifiedUserId))
        {
            return Results.Unauthorized();
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;

        return Results.Ok(new
        {
            userId = verifiedUserId,
            userName = userName,
            role = role
        });
    }
}