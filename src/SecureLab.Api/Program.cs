using StackExchange.Redis;
using SecureLab.Api.Security;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;
using SecureLab.Api.Scaffolding;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddScoped<IncidentQueries>();
builder.Services.AddSingleton<IAuthorizationHandler, IncidentAuthorizationHandler>();

builder.AddLab03Identity();

builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-SecureLab-CSRF";
});

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                  .WithMethods("GET")
                  .WithHeaders("X-Lab-Cors-Probe")
                  .AllowCredentials();
        });
    });
}

var globalPermitLimit = builder.Configuration.GetValue("RateLimiting:GlobalPermitLimit", 5);
var searchPermitLimit = builder.Configuration.GetValue("RateLimiting:SearchPermitLimit", 10);

var redisConnStr = builder.Configuration["Redis:ConnectionString"];
IConnectionMultiplexer? redisMultiplexer = null;
if (!string.IsNullOrWhiteSpace(redisConnStr))
{
    var cfg = ConfigurationOptions.Parse(redisConnStr);
    cfg.AbortOnConnectFail = false;
    cfg.ConnectTimeout = 1000;
    cfg.SyncTimeout = 1000;
    redisMultiplexer = ConnectionMultiplexer.Connect(cfg);
}

builder.Services.AddSingleton(sp => new RedisSearchRateLimiter(
    redisMultiplexer,
    sp.GetRequiredService<ILogger<RedisSearchRateLimiter>>(),
    searchPermitLimit,
    windowSeconds: 30));

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "global",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = globalPermitLimit,
                Window = TimeSpan.FromSeconds(10)
            }));

    options.AddPolicy("search-per-user", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = searchPermitLimit,
                Window = TimeSpan.FromSeconds(30),
                QueueLimit = 0
            }));
});

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

var csp = "default-src 'self'; frame-ancestors 'none'";

app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";

        var isDevelopmentApiReference =
            app.Environment.IsDevelopment()
            && context.Request.Path.StartsWithSegments("/scalar");

        if (!isDevelopmentApiReference)
        {
            context.Response.Headers["Content-Security-Policy"] = csp;
        }

        return Task.CompletedTask;
    });

    await next(context);
});

app.UseExceptionHandler();
app.UseStatusCodePages();

app.UseRouting();

if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    if (HttpMethods.IsGet(context.Request.Method)
        && context.Request.Path.Equals("/api/incidents", StringComparison.OrdinalIgnoreCase))
    {
        var redisLimiter = context.RequestServices.GetRequiredService<RedisSearchRateLimiter>();
        if (redisLimiter.IsConfigured)
        {
            var partitionKey = context.User.Identity?.Name ?? "anonymous";
            var decision = await redisLimiter.TryAcquireAsync(partitionKey);
            if (decision == false)
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.Response.Headers.RetryAfter = "30";
                await Results.Problem(
                    title: "Too Many Requests",
                    detail: "Distributed search rate limit exceeded.",
                    statusCode: StatusCodes.Status429TooManyRequests).ExecuteAsync(context);
                return;
            }
        }
    }

    await next(context);
});

app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

app.MapGet("/api/csrf-token", (IAntiforgery antiforgery, HttpContext http) =>
{
    var tokens = antiforgery.GetAndStoreTokens(http);
    return Results.Ok(new { token = tokens.RequestToken });
})
.RequireAuthorization()
.WithName("GetCsrfToken");

app.MapIncidentEndpoints();
app.MapLab03Identity();
app.MapLab02Endpoints();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;