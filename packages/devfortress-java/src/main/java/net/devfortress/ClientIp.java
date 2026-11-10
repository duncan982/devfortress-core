package net.devfortress;

/**
 * Picks the end-user IP for an event from what the request shows.
 *
 * <p>Precedence: the first X-Forwarded-For entry, then X-Real-IP, then the
 * socket address, then {@code "0.0.0.0"}. A candidate that is not an IP
 * address is skipped, so a malformed forwarded header cannot poison a
 * batch. Mirrors {@code packages/devfortress-go/clientip.go}.
 */
public final class ClientIp {
    private ClientIp() {
    }

    public static String resolve(String forwardedFor, String realIp, String remoteAddr) {
        String first = "";
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            int comma = forwardedFor.indexOf(',');
            first = (comma == -1 ? forwardedFor : forwardedFor.substring(0, comma)).trim();
        }
        String[] candidates = {first, trim(realIp), trim(remoteAddr)};
        for (String candidate : candidates) {
            if (!candidate.isEmpty() && isIpAddress(candidate)) {
                return candidate;
            }
        }
        return "0.0.0.0";
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }

    private static boolean isIpAddress(String candidate) {
        try {
            return InetAddressValidator.isValid(candidate);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Tiny IPv4/IPv6 literal validator — avoids a DNS lookup, unlike InetAddress.getByName. */
    private static final class InetAddressValidator {
        private static final java.util.regex.Pattern IPV4 = java.util.regex.Pattern.compile(
                "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

        static boolean isValid(String candidate) {
            if (IPV4.matcher(candidate).matches()) {
                return true;
            }
            return isValidIpv6(candidate);
        }

        private static boolean isValidIpv6(String candidate) {
            if (!candidate.contains(":")) {
                return false;
            }
            // InetAddress.getByName resolves a literal IP address purely by syntax
            // (per its javadoc: "If a literal IP address is supplied, only the
            // validity of the address format is checked") — no DNS lookup happens
            // for a string that parses as a literal, which every IPv6 candidate
            // here does by virtue of containing a colon.
            try {
                return java.net.InetAddress.getByName(candidate) instanceof java.net.Inet6Address;
            } catch (java.net.UnknownHostException e) {
                return false;
            }
        }
    }
}
