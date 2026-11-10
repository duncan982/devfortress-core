using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

public class ClassifierTests
{
    [Fact]
    public void DetectsSqlInjection()
    {
        Assert.Equal(["sql_injection"], Classifier.DetectSuspicious("id=1 OR 1=1"));
        Assert.Equal(["sql_injection"], Classifier.DetectSuspicious("' OR '1'='1"));
        Assert.Equal(["sql_injection"], Classifier.DetectSuspicious("1 UNION SELECT password FROM users"));
    }

    [Fact]
    public void DetectsSqlInjectionAfterPercentDecoding()
    {
        Assert.Equal(["sql_injection"], Classifier.DetectSuspicious("id=1%20OR%201=1"));
    }

    [Fact]
    public void DoesNotFalsePositiveOnALiteralPercentSign()
    {
        Assert.Empty(Classifier.DetectSuspicious("discount=50%"));
    }

    [Fact]
    public void DetectsXss()
    {
        Assert.Equal(["xss"], Classifier.DetectSuspicious("<script>alert(1)</script>"));
        Assert.Equal(["xss"], Classifier.DetectSuspicious("javascript:alert(1)"));
    }

    [Fact]
    public void DetectsPathTraversal()
    {
        Assert.Equal(["path_traversal"], Classifier.DetectSuspicious("../../etc/passwd"));
    }

    [Fact]
    public void NoSuspiciousPatternsForOrdinaryText()
    {
        Assert.Empty(Classifier.DetectSuspicious("/api/items?page=2"));
    }

    [Fact]
    public void BuildEventReturnsNullForAnOrdinary200()
    {
        var @event = Classifier.BuildEvent(new Classifier.ClassifyInput(
            "203.0.113.7", "GET", "/api/items", 200, 12, "curl/8.0", "", null));
        Assert.Null(@event);
    }

    [Fact]
    public void BuildEventClassifiesAuthFailure()
    {
        var @event = Classifier.BuildEvent(new Classifier.ClassifyInput(
            "203.0.113.7", "POST", "/login", 401, 8, "curl/8.0", "", null))!;
        Assert.Equal("auth_failure", @event["eventType"]);
        Assert.Equal("MEDIUM", @event["severity"]);
        Assert.Equal("blocked", @event["actionTaken"]);
        Assert.Equal("pre_auth", @event["authPhase"]);
    }

    [Fact]
    public void BuildEventClassifiesSuspiciousPatternOverStatusCode()
    {
        var @event = Classifier.BuildEvent(new Classifier.ClassifyInput(
            "203.0.113.7", "GET", "/search", 200, 5, "curl/8.0", "q=1' OR '1'='1", null))!;
        Assert.Equal("suspicious_pattern", @event["eventType"]);
        Assert.Equal("HIGH", @event["severity"]);
        Assert.Equal("flagged", @event["actionTaken"]);
    }

    [Fact]
    public void BuildEventMarksPostAuthWhenUserIdPresent()
    {
        var @event = Classifier.BuildEvent(new Classifier.ClassifyInput(
            "203.0.113.7", "GET", "/account", 500, 20, "curl/8.0", "", "user_42"))!;
        Assert.Equal("post_auth", @event["authPhase"]);
        Assert.Equal("5xx_error", @event["eventType"]);
        Assert.Equal("HIGH", @event["severity"]);
    }
}
