package net.devfortress;

import java.util.Map;

/** Receives delivery-failure log lines from {@link Client}. Optional — a null logger disables logging. */
public interface Logger {
    void log(String level, String message, Map<String, Object> fields);
}
