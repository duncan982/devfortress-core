namespace DevFortress;

/// <summary>Outcome of one delivery attempt (or batch chunk) — never an exception.</summary>
public sealed class DeliveryResult
{
    public bool Ok { get; }
    public int StatusCode { get; }
    public object? Body { get; }
    public Exception? Error { get; }
    public int Attempts { get; }

    public DeliveryResult(bool ok, int statusCode, object? body, Exception? error, int attempts)
    {
        Ok = ok;
        StatusCode = statusCode;
        Body = body;
        Error = error;
        Attempts = attempts;
    }

    internal static DeliveryResult Failed(Exception error, int attempts) => new(false, 0, null, error, attempts);

    internal static DeliveryResult HttpFailure(int statusCode, object? body, Exception error, int attempts) =>
        new(false, statusCode, body, error, attempts);
}
