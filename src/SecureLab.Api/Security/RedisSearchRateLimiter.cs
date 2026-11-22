using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace SecureLab.Api.Security;

public sealed class SearchRateLimitOptions
{
    public int PermitLimit { get; set; } = 10;
    public TimeSpan Window { get; set; } = TimeSpan.FromSeconds(30);
    public string KeyPrefix { get; set; } = "search:";
}

public readonly record struct RateLimitDecision(bool Allowed, int RetryAfterSeconds);

public sealed class RedisSearchRateLimiter
{
    private const string Script = @"
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); ttl = tonumber(ARGV[1]) end
return {c, ttl}";

    private readonly IConnectionMultiplexer? _redis;
    private readonly ILogger<RedisSearchRateLimiter> _logger;
    private readonly SearchRateLimitOptions _options;
    private readonly LocalFixedWindowFallback _local;

    private long _pauseUntil;
    private int _degraded;

    public RedisSearchRateLimiter(
        IConnectionMultiplexer? redis,
        ILogger<RedisSearchRateLimiter> logger,
        SearchRateLimitOptions options)
    {
        _redis = redis;
        _logger = logger;
        _options = options;
        _local = new LocalFixedWindowFallback(options.PermitLimit, options.Window);
    }

    public bool IsConfigured => _redis is not null;

    public async ValueTask<RateLimitDecision> TryAcquireAsync(string partitionKey)
    {
        if (_redis is null)
        {
            return _local.AttemptAcquire(partitionKey);
        }

        // 1) Швидкий шлях без I/O: якщо Redis у паузі — рішення дає локальний limiter
        if (Environment.TickCount64 < Volatile.Read(ref _pauseUntil))
        {
            return _local.AttemptAcquire(partitionKey);
        }

        var windowMs = Math.Max(1, (long)_options.Window.TotalMilliseconds);
        var redisKey = (RedisKey)(_options.KeyPrefix + partitionKey);

        try
        {
            var db = _redis.GetDatabase();
            var rawResult = await db
                .ScriptEvaluateAsync(Script, new[] { redisKey }, new RedisValue[] { windowMs })
                .WaitAsync(TimeSpan.FromMilliseconds(100));

            var res = (RedisResult[])rawResult!;
            if (Interlocked.Exchange(ref _degraded, 0) == 1)
            {
                _logger.LogInformation("Redis відновлено, лічильник знову спільний");
            }

            var count = (long)res[0];
            var ttlMs = (long)res[1];

            if (count <= _options.PermitLimit)
            {
                return new RateLimitDecision(true, 0);
            }

            var retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(ttlMs / 1000.0));
            return new RateLimitDecision(false, retryAfterSeconds);
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException)
        {
            Volatile.Write(ref _pauseUntil, Environment.TickCount64 + 10_000);
            if (Interlocked.Exchange(ref _degraded, 1) == 0)
            {
                _logger.LogWarning(ex, "Redis недоступний — деградований режим: локальний limiter");
            }

            return _local.AttemptAcquire(partitionKey);
        }
    }

    private sealed class LocalFixedWindowFallback(int permitLimit, TimeSpan window)
    {
        private readonly ConcurrentDictionary<string, WindowState> _states = new();
        private readonly long _windowMs = Math.Max(1, (long)window.TotalMilliseconds);

        public RateLimitDecision AttemptAcquire(string key)
        {
            var now = Environment.TickCount64;
            var state = _states.GetOrAdd(key, _ => new WindowState(now + _windowMs, 0));

            lock (state)
            {
                if (now >= state.ResetAtTick)
                {
                    state.ResetAtTick = now + _windowMs;
                    state.Count = 0;
                }

                state.Count++;
                if (state.Count <= permitLimit)
                {
                    return new RateLimitDecision(true, 0);
                }

                var remainingMs = Math.Max(1_000, state.ResetAtTick - now);
                var retryAfter = (int)Math.Ceiling(remainingMs / 1000.0);
                return new RateLimitDecision(false, retryAfter);
            }
        }

        private sealed class WindowState(long resetAtTick, int count)
        {
            public long ResetAtTick = resetAtTick;
            public int Count = count;
        }
    }
}