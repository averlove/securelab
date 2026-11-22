using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Security;
using StackExchange.Redis;
using Xunit;

namespace SecureLab.Api.Tests;

public sealed class RedisSearchRateLimiterTests
{
    private sealed class ListLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }

    [Fact]
    public async Task LiveRedis_SharesLimitAcrossInstances_AndResetsAfterWindow()
    {
        var cfg = ConfigurationOptions.Parse("127.0.0.1:6379");
        cfg.AbortOnConnectFail = true;
        cfg.ConnectTimeout = 500;
        cfg.AsyncTimeout = 200;

        using var mux = await ConnectionMultiplexer.ConnectAsync(cfg);

        var options = new SearchRateLimitOptions
        {
            PermitLimit = 3,
            Window = TimeSpan.FromMilliseconds(1200),
            KeyPrefix = $"test-live-{Guid.NewGuid():N}:"
        };

        var limiterA = new RedisSearchRateLimiter(mux, new ListLogger<RedisSearchRateLimiter>(), options);
        var limiterB = new RedisSearchRateLimiter(mux, new ListLogger<RedisSearchRateLimiter>(), options);

        const string userKey = "alice";

        Assert.True((await limiterA.TryAcquireAsync(userKey)).Allowed);
        Assert.True((await limiterB.TryAcquireAsync(userKey)).Allowed);
        Assert.True((await limiterA.TryAcquireAsync(userKey)).Allowed);

        var fourth = await limiterB.TryAcquireAsync(userKey);
        Assert.False(fourth.Allowed);
        Assert.True(fourth.RetryAfterSeconds >= 1);

        await Task.Delay(1300);

        var afterWindow = await limiterA.TryAcquireAsync(userKey);
        Assert.True(afterWindow.Allowed);
    }

    [Fact]
    public async Task UnavailableRedis_FallsBackToLocalLimiter_PausesAndLogsSingleWarning()
    {
        var cfg = ConfigurationOptions.Parse("127.0.0.1:6390");
        cfg.AbortOnConnectFail = false;
        cfg.ConnectTimeout = 200;
        cfg.AsyncTimeout = 100;

        using var mux = ConnectionMultiplexer.Connect(cfg);
        var logger = new ListLogger<RedisSearchRateLimiter>();

        var options = new SearchRateLimitOptions
        {
            PermitLimit = 3,
            Window = TimeSpan.FromSeconds(30),
            KeyPrefix = $"test-fallback-{Guid.NewGuid():N}:"
        };

        var limiter = new RedisSearchRateLimiter(mux, logger, options);
        const string userKey = "alice";

        var swFirst = Stopwatch.StartNew();
        Assert.True((await limiter.TryAcquireAsync(userKey)).Allowed);
        swFirst.Stop();

        Assert.True((await limiter.TryAcquireAsync(userKey)).Allowed);
        Assert.True((await limiter.TryAcquireAsync(userKey)).Allowed);

        var fourth = await limiter.TryAcquireAsync(userKey);
        Assert.False(fourth.Allowed);
        Assert.True(fourth.RetryAfterSeconds >= 1);

        var swFast = Stopwatch.StartNew();
        _ = await limiter.TryAcquireAsync(userKey);
        swFast.Stop();

        Assert.True(swFast.ElapsedMilliseconds < 100, $"Expected fast pause path, got {swFast.ElapsedMilliseconds} ms");

        var warningCount = logger.Entries.Count(e => e.Level == LogLevel.Warning);
        Assert.Equal(1, warningCount);
    }
}