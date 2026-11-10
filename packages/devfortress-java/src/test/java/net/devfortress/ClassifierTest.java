package net.devfortress;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClassifierTest {
    @Test
    void detectsSqlInjection() {
        assertEquals(List.of("sql_injection"), Classifier.detectSuspicious("id=1 OR 1=1"));
        assertEquals(List.of("sql_injection"), Classifier.detectSuspicious("' OR '1'='1"));
        assertEquals(List.of("sql_injection"), Classifier.detectSuspicious("1 UNION SELECT password FROM users"));
    }

    @Test
    void detectsSqlInjectionAfterPercentDecoding() {
        assertEquals(List.of("sql_injection"), Classifier.detectSuspicious("id=1%20OR%201=1"));
    }

    @Test
    void doesNotFalsePositiveOnALiteralPercentSign() {
        assertTrue(Classifier.detectSuspicious("discount=50%").isEmpty());
    }

    @Test
    void detectsXss() {
        assertEquals(List.of("xss"), Classifier.detectSuspicious("<script>alert(1)</script>"));
        assertEquals(List.of("xss"), Classifier.detectSuspicious("javascript:alert(1)"));
    }

    @Test
    void detectsPathTraversal() {
        assertEquals(List.of("path_traversal"), Classifier.detectSuspicious("../../etc/passwd"));
    }

    @Test
    void noSuspiciousPatternsForOrdinaryText() {
        assertTrue(Classifier.detectSuspicious("/api/items?page=2").isEmpty());
    }

    @Test
    void buildEventReturnsNullForAnOrdinary200() {
        var event = Classifier.buildEvent(new Classifier.ClassifyInput(
                "203.0.113.7", "GET", "/api/items", 200, 12, "curl/8.0", "", null));
        assertNull(event);
    }

    @Test
    void buildEventClassifiesAuthFailure() {
        Map<String, Object> event = Classifier.buildEvent(new Classifier.ClassifyInput(
                "203.0.113.7", "POST", "/login", 401, 8, "curl/8.0", "", null));
        assertEquals("auth_failure", event.get("eventType"));
        assertEquals("MEDIUM", event.get("severity"));
        assertEquals("blocked", event.get("actionTaken"));
        assertEquals("pre_auth", event.get("authPhase"));
    }

    @Test
    void buildEventClassifiesSuspiciousPatternOverStatusCode() {
        Map<String, Object> event = Classifier.buildEvent(new Classifier.ClassifyInput(
                "203.0.113.7", "GET", "/search", 200, 5, "curl/8.0", "q=1' OR '1'='1", null));
        assertEquals("suspicious_pattern", event.get("eventType"));
        assertEquals("HIGH", event.get("severity"));
        assertEquals("flagged", event.get("actionTaken"));
    }

    @Test
    void buildEventMarksPostAuthWhenUserIdPresent() {
        Map<String, Object> event = Classifier.buildEvent(new Classifier.ClassifyInput(
                "203.0.113.7", "GET", "/account", 500, 20, "curl/8.0", "", "user_42"));
        assertEquals("post_auth", event.get("authPhase"));
        assertEquals("5xx_error", event.get("eventType"));
        assertEquals("HIGH", event.get("severity"));
    }
}
