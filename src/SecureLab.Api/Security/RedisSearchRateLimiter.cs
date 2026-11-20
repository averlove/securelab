using StackExchange.Redis;

namespace SecureLab.Api.Security;

public sealed class RedisSearchRateLimiter
{
    private readonly IConnectionMultiplexer? _redis;
    private readonly ILogger<RedisSearchRateLimiter> _logger;
    private readonly int _permitLimit;
    private readonly int _windowSeconds;

    public RedisSearchRateLimiter(
        IConnectionMultiplexer? redis,
        ILogger<RedisSearchRateLimiter> logger,
        int permitLimit,
        int windowSeconds = 30)
    {
        _redis = redis;
        _logger = logger;
        _permitLimit = permitLimit;
        _windowSeconds = windowSeconds;
    }

    public bool IsConfigured => _redis is not null;

    public async Task<bool?> TryAcquireAsync(string partitionKey)
    {
        if (_redis is null)
            return null;

        try
        {
            var db = _redis.GetDatabase();
            var windowId = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / _windowSeconds;
            var key = $"ratelimit:search:{partitionKey}:{windowId}";

            var count = await db.StringIncrementAsync(key);
            if (count == 1)
            {
                await db.KeyExpireAsync(key, TimeSpan.FromSeconds(_windowSeconds));
            }

            return count <= _permitLimit;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Redis rate limiter unavailable (fail-open fallback to in-memory limiter) for partition {PartitionKey}",
                partitionKey);
            return null;
        }
    }
}