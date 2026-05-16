package burp;

import java.security.SecureRandom;

/**
 * Pre-scan sanity check borrowed from the Python {@code tilde_enum.py}
 * {@code initialCheckUrl}: fire a request for a guaranteed-not-there
 * filename and decide whether the server is "well-behaved" enough for the
 * scanner's heuristics to be trusted.
 *
 * <p>If the target returns 200 for a random 13-char {@code .htm} file, the
 * upstream is either a captive portal, a single-page app rewriting every
 * route to the same response, or a WAF normalizing errors — and the
 * scanner's "valid vs invalid" body diff will be unreliable. We warn the
 * user (loud) but never abort: experts may still want to attempt the scan.
 *
 * <p>Pure logic so the classifier can be unit-tested without a live target.
 */
public final class BaselineProbe {

    public enum Verdict {
        /** Server returned 404 — the diff heuristic will work as designed. */
        EXPECTED_404,
        /** Server returned 200 — custom error pages or SPA, body-diff unreliable. */
        SUSPICIOUS_200,
        /** 301/302/3xx — captive portal / login wall, scan will likely chase the redirect. */
        REDIRECT,
        /** 401 / 403 — every probe will look like the same auth wall response. */
        AUTH_WALL,
        /** 5xx — server stressed; pause and retry. */
        SERVER_ERROR,
        /** Anything else, including network failure ({@code status < 0}). */
        UNKNOWN
    }

    public static final class Result {
        public final Verdict verdict;
        public final int statusCode;
        public final String probeFilename;

        public Result(Verdict verdict, int statusCode, String probeFilename) {
            this.verdict = verdict;
            this.statusCode = statusCode;
            this.probeFilename = probeFilename;
        }

        /** UI-ready summary line. Empty when the verdict is {@link Verdict#EXPECTED_404}. */
        public String message() {
            return switch (verdict) {
                case EXPECTED_404 -> "";
                case SUSPICIOUS_200 -> String.format(
                        "[!] WARNING: target returned HTTP 200 for nonexistent file \"%s\" — likely a custom error page or SPA. "
                                + "Body-diff heuristic may produce false negatives.",
                        probeFilename);
                case REDIRECT -> String.format(
                        "[!] WARNING: target returned HTTP %d (redirect) for nonexistent file \"%s\" — auth wall or captive portal likely. "
                                + "Scan results may follow the redirect instead of the real backend.",
                        statusCode, probeFilename);
                case AUTH_WALL -> String.format(
                        "[!] WARNING: target returned HTTP %d for nonexistent file \"%s\" — every probe will hit the same auth response. "
                                + "Consider authenticating first or supplying a session cookie in the request template.",
                        statusCode, probeFilename);
                case SERVER_ERROR -> String.format(
                        "[!] WARNING: target returned HTTP %d for nonexistent file \"%s\" — server-side error, results unreliable.",
                        statusCode, probeFilename);
                case UNKNOWN -> String.format(
                        "[!] WARNING: baseline probe for \"%s\" returned an unexpected status (%d). "
                                + "Scan may proceed but results should be interpreted with care.",
                        probeFilename, statusCode);
            };
        }
    }

    private static final SecureRandom RNG = new SecureRandom();
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private BaselineProbe() {}

    /** Mirrors the Python tool: random 13-char alphanumeric + {@code .htm}. */
    public static String randomFilename() {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 13; i++) sb.append(ALPHABET.charAt(RNG.nextInt(ALPHABET.length())));
        sb.append(".htm");
        return sb.toString();
    }

    /** Pure-logic classifier — visible for tests. */
    public static Verdict classify(int statusCode) {
        if (statusCode == 404) return Verdict.EXPECTED_404;
        if (statusCode == 200) return Verdict.SUSPICIOUS_200;
        if (statusCode == 401 || statusCode == 403) return Verdict.AUTH_WALL;
        if (statusCode >= 300 && statusCode < 400) return Verdict.REDIRECT;
        if (statusCode >= 500 && statusCode < 600) return Verdict.SERVER_ERROR;
        return Verdict.UNKNOWN;
    }

    public static Result build(int statusCode, String probeFilename) {
        return new Result(classify(statusCode), statusCode, probeFilename);
    }
}
