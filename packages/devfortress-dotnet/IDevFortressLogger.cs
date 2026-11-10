namespace DevFortress;

/// <summary>Receives delivery-failure log lines from <see cref="Client"/>. Optional — a null logger disables logging.</summary>
public interface IDevFortressLogger
{
    void Log(string level, string message, IReadOnlyDictionary<string, object?> fields);
}
