package net.devfortress.springboot;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.devfortress.Client;
import net.devfortress.ClientIp;
import net.devfortress.InternalClosedLoopEngine;
import net.devfortress.Observer;
import net.devfortress.TierGate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Servlet filter that observes each request (method, path, status, timing,
 * client IP and classifier result) and reports a security event for it, the
 * same way {@code devfortress-laravel}'s middleware does for Laravel and
 * {@code devfortress-rails}'s Rack middleware does for Rails: {@code
 * doFilterInternal} only measures the request — nothing here changes or
 * fails the response.
 *
 * <p>Reporting happens in a {@code finally} block, AFTER {@code
 * filterChain.doFilter(...)} returns — by which point the servlet container
 * has already written the response — the Spring-appropriate equivalent of
 * Laravel's {@code terminate()} hook and Rack's {@code #close} hook, both of
 * which likewise run only once the response has gone out. It calls {@link
 * Observer#observeAndFlush}, not {@link Observer#observe}, so a single
 * request is delivered even under sparse traffic: this is the Go SDK's gin
 * adapter's original sparse-traffic gap (see the Java SDK audit notes),
 * fixed after the fact there and ported here from the start — do not
 * change this to {@code observe} without also wiring in some other
 * guaranteed flush path, or a lone event can sit queued and undelivered
 * indefinitely.
 *
 * <p>Reporting itself runs on the {@link Client}'s own detached executor
 * (see {@link Observer}), so it adds no latency to the response — the
 * filter thread returns to the container immediately after handing the
 * observation off.
 *
 * <p><b>Internal/hybrid closed-loop mode (TODO 407 port):</b> when {@link
 * Client#getMode} is {@code internal} or {@code hybrid}, {@code
 * doFilterInternal} ALSO runs a pre-response gate before {@code
 * filterChain.doFilter(...)}: it builds an {@link
 * InternalClosedLoopEngine.InternalCLRequest} from the incoming {@link
 * HttpServletRequest} and calls {@link Client#observe}. If the request is
 * flagged, this short-circuits with a 403 JSON response and the wrapped
 * application never sees the request. In {@code external} mode (the
 * default), {@code client.getMode()} is {@code EXTERNAL} and this gate is
 * skipped entirely — behavior is unchanged from before this port.
 *
 * <p>Request body inspection is explicitly out of scope for this gate:
 * {@code HttpServletRequest}'s body is a single-read stream, and safely
 * buffering/rewinding it for the downstream application (e.g. via
 * Spring's {@code ContentCachingRequestWrapper}) is a separate concern
 * this port does not take on — matching the Python port's FastAPI gate's
 * same documented path/query/headers-only scope limitation. Path- and
 * query-based rules (SQLi, XSS, path traversal, scanner signatures,
 * sensitive-file access, credential-stuffing paths) still fire; a
 * body-only attack payload is missed here.
 */
public class DevFortressFilter extends OncePerRequestFilter {
    private static final List<String> DEFAULT_EXCLUDE_PATHS = List.of("/health", "/up");

    private final Client client;
    private final List<String> excludePaths;

    public DevFortressFilter(Client client) {
        this(client, DEFAULT_EXCLUDE_PATHS);
    }

    /** {@code excludePaths} are path prefixes to skip reporting for (default {@code ["/health", "/up"]}). */
    public DevFortressFilter(Client client, List<String> excludePaths) {
        this.client = client;
        this.excludePaths = excludePaths;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        TierGate.CLMode mode = client.getMode();
        if ((mode == TierGate.CLMode.INTERNAL || mode == TierGate.CLMode.HYBRID)
                && !isExcluded(request.getRequestURI())
                && internalGate(request, response)) {
            return; // blocked — short-circuited before the filter chain / application
        }

        long started = System.nanoTime();
        // filterChain.doFilter is intentionally OUTSIDE the try's catch (there is
        // none): an exception from the wrapped application must propagate exactly
        // as it would without this filter. Only the reporting in the finally block
        // below is allowed to fail silently.
        try {
            filterChain.doFilter(request, response);
        } finally {
            report(request, response, (System.nanoTime() - started) / 1_000_000);
        }
    }

    /**
     * Returns {@code true} if the request was blocked (the caller must not
     * forward to the filter chain). Never throws — any failure to build the
     * request shape or evaluate it falls through to {@code false} (request
     * allowed), matching this filter's existing "reporting must never affect
     * the application" discipline in {@link #report}.
     */
    private boolean internalGate(HttpServletRequest request, HttpServletResponse response) {
        try {
            Map<String, String> headers = new LinkedHashMap<>();
            Enumeration<String> names = request.getHeaderNames();
            if (names != null) {
                while (names.hasMoreElements()) {
                    String name = names.nextElement();
                    headers.put(name, request.getHeader(name));
                }
            }

            InternalClosedLoopEngine.InternalCLRequest req = InternalClosedLoopEngine.InternalCLRequest
                    .builder(
                            ClientIp.resolve(request.getHeader("X-Forwarded-For"), request.getHeader("X-Real-IP"), request.getRemoteAddr()),
                            request.getMethod(),
                            request.getRequestURI())
                    .userAgent(request.getHeader("User-Agent"))
                    .query(request.getQueryString())
                    .headers(headers)
                    .build();

            Client.ObserveResult result = client.observe(req);
            if (result != null && result.flagged()) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write(
                        "{\"error\":\"blocked\",\"reason\":\"" + result.decision().wireValue()
                                + "\",\"eventId\":\"" + result.eventId() + "\"}");
                return true;
            }
            return false;
        } catch (RuntimeException | IOException e) {
            logger.debug("devfortress: internal gate evaluation failed, allowing request", e);
            return false;
        }
    }

    private void report(HttpServletRequest request, HttpServletResponse response, long latencyMs) {
        String path = request.getRequestURI();
        if (isExcluded(path)) {
            return;
        }
        try {
            Observer.Input input = new Observer.Input(
                    request.getMethod(),
                    path,
                    request.getQueryString(),
                    response.getStatus(),
                    (int) latencyMs,
                    request.getHeader("User-Agent"),
                    request.getHeader("X-Forwarded-For"),
                    request.getHeader("X-Real-IP"),
                    request.getRemoteAddr(),
                    asString(request.getAttribute("devfortress.userId")));
            Observer.observeAndFlush(client, input);
        } catch (RuntimeException e) {
            // Reporting must never affect the application; the client already logs
            // delivery failures, so a failure building the report itself (a
            // malformed request, an unreadable header) must not surface either.
            logger.debug("devfortress: could not build/queue a security event", e);
        }
    }

    private boolean isExcluded(String path) {
        if (path == null) {
            return false;
        }
        for (String prefix : excludePaths) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static String asString(Object value) {
        return value == null ? null : value.toString();
    }
}
