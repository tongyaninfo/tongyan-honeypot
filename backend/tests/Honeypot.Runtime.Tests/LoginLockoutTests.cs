using Honeypot.Api.Service.impl;
using Microsoft.AspNetCore.Builder;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class LoginLockoutTests
{
    private const string Username = "isolated-admin";
    private const string Password = "Isolated-test-Password123!";

    [Fact]
    public async Task ConsecutiveFailuresLockAllNewLoginsAndPersistThroughRestart()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Configuration["Honeypot:DataDirectory"] = Path.Combine(Path.GetTempPath(), $"honeypot-lockout-{Guid.NewGuid():N}");
        var time = new TestClock();
        using var identity = new FileUserIdentityService(builder.Configuration, builder.Environment, clock: time);
        Assert.True((await identity.InitializeFirstAdminAsync(Username, Password)).Succeeded);
        var existing = Assert.IsType<Honeypot.Api.Models.LoginResult>((await identity.LoginAsync(Username, Password)).Session);

        for (var attempt = 0; attempt < 4; attempt++)
        {
            var failure = await identity.LoginAsync("unknown-user", "incorrect");
            Assert.Null(failure.Session);
            Assert.Null(failure.LockedUntilUtc);
        }
        var locked = await identity.LoginAsync(Username, "incorrect");
        Assert.True(locked.LockoutStarted);
        Assert.Equal(time.GetUtcNow().AddMinutes(30), locked.LockedUntilUtc);
        Assert.True(identity.TryAuthenticate(existing.AccessToken, out _));

        using var restarted = new FileUserIdentityService(builder.Configuration, builder.Environment, clock: time);
        var previouslyLocked = await restarted.LoginAsync(Username, Password);
        Assert.False(previouslyLocked.LockoutStarted);
        Assert.Equal(locked.LockedUntilUtc, previouslyLocked.LockedUntilUtc);
        time.Advance(TimeSpan.FromMinutes(30));
        Assert.NotNull((await restarted.LoginAsync(Username, Password)).Session);
    }

    [Fact]
    public async Task SuccessfulLoginResetsFailuresAndCustomPolicyIsApplied()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Configuration["Honeypot:DataDirectory"] = Path.Combine(Path.GetTempPath(), $"honeypot-lockout-{Guid.NewGuid():N}");
        builder.Configuration["Honeypot:LoginLockout:MaxFailedAttempts"] = "2";
        builder.Configuration["Honeypot:LoginLockout:DurationMinutes"] = "3";
        var time = new TestClock();
        using var identity = new FileUserIdentityService(builder.Configuration, builder.Environment, clock: time);
        Assert.True((await identity.InitializeFirstAdminAsync(Username, Password)).Succeeded);
        Assert.Null((await identity.LoginAsync("unknown-user", "incorrect")).LockedUntilUtc);
        Assert.NotNull((await identity.LoginAsync(Username, Password)).Session);
        Assert.Null((await identity.LoginAsync("unknown-user", "incorrect")).LockedUntilUtc);
        Assert.Equal(time.GetUtcNow().AddMinutes(3), (await identity.LoginAsync("unknown-user", "incorrect")).LockedUntilUtc);
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 14, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}
