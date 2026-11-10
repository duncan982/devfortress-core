package net.devfortress;

/** Outcome of one delivery attempt (or batch chunk) — never an exception. */
public final class DeliveryResult {
    public final boolean ok;
    public final int statusCode;
    public final Object body;
    public final Exception error;
    public final int attempts;

    public DeliveryResult(boolean ok, int statusCode, Object body, Exception error, int attempts) {
        this.ok = ok;
        this.statusCode = statusCode;
        this.body = body;
        this.error = error;
        this.attempts = attempts;
    }

    static DeliveryResult failed(Exception error, int attempts) {
        return new DeliveryResult(false, 0, null, error, attempts);
    }

    static DeliveryResult http(int statusCode, Object body, int attempts) {
        return new DeliveryResult(statusCode >= 200 && statusCode < 300, statusCode, body, null, attempts);
    }

    static DeliveryResult httpFailure(int statusCode, Object body, Exception error, int attempts) {
        return new DeliveryResult(false, statusCode, body, error, attempts);
    }
}
