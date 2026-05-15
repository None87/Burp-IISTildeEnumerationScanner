package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Step beyond enumeration: take the candidate wordlist produced by
 * {@link DictionaryGenerator} and actually request each path on the target
 * server, recording only those whose HTTP status code matches the configured
 * success set.
 *
 * <p>This is the analogue of piping {@code tilde_enum.py --dict-only} into
 * {@code ffuf} — except it runs inline so analysts don't have to leave Burp.
 *
 * <p>The HTTP layer is injected as a {@link RequestSender} so the class can
 * be unit-tested without a live target. In production, {@code BurpExtender}
 * supplies a sender that wraps {@link Requester} + Burp's response analyzer.
 */
public final class PathFuzzer extends Thread {

    /** Default set matching the Python tool's README integration examples. */
    public static final Set<Integer> DEFAULT_SUCCESS_CODES =
            Collections.unmodifiableSet(new java.util.HashSet<>(Arrays.asList(200, 204, 301, 302, 307, 401, 403)));

    /** Result of probing one candidate. {@code length == -1} means "unknown / error". */
    public static final class ResponseInfo {
        public final int status;
        public final int length;

        public ResponseInfo(int status, int length) {
            this.status = status;
            this.length = length;
        }

        public static ResponseInfo statusOnly(int status) {
            return new ResponseInfo(status, -1);
        }

        public static final ResponseInfo ERROR = new ResponseInfo(-1, -1);
    }

    /** Adapter for HTTP requests. */
    public interface RequestSender {
        ResponseInfo sendGet(String relativePath);
    }

    /** Hook for streaming per-candidate progress + completion to the UI. */
    public interface ProgressReporter {
        void onAttempt(String candidate, int status, int length, boolean hit);
        void onFinish(int sent, int hits);
    }

    public static final class Hit {
        public final String candidate;
        public final int statusCode;
        public final int length;

        public Hit(String candidate, int statusCode, int length) {
            this.candidate = candidate;
            this.statusCode = statusCode;
            this.length = length;
        }
    }

    private final List<String> candidates;
    private final RequestSender sender;
    private final Set<Integer> successCodes;
    private final int nThreads;
    private final ProgressReporter reporter;

    private final CopyOnWriteArrayList<Hit> hits = new CopyOnWriteArrayList<>();
    private final AtomicInteger sent = new AtomicInteger(0);
    private volatile boolean stopping = false;
    private ThreadPoolExecutor pool;

    public PathFuzzer(List<String> candidates, RequestSender sender,
                      Set<Integer> successCodes, int nThreads, ProgressReporter reporter) {
        this.candidates = candidates == null ? new ArrayList<>() : new ArrayList<>(new LinkedHashSet<>(candidates));
        this.sender = sender;
        this.successCodes = successCodes == null || successCodes.isEmpty() ? DEFAULT_SUCCESS_CODES : successCodes;
        this.nThreads = Math.max(1, nThreads);
        this.reporter = reporter;
    }

    public List<Hit> getHits() { return new ArrayList<>(hits); }
    public int sentCount() { return sent.get(); }
    public int candidateCount() { return candidates.size(); }

    @Override
    public void interrupt() {
        stopping = true;
        if (pool != null) pool.shutdownNow();
        super.interrupt();
    }

    @Override
    public void run() {
        if (candidates.isEmpty() || sender == null) {
            if (reporter != null) reporter.onFinish(0, 0);
            return;
        }
        pool = new ThreadPoolExecutor(nThreads, nThreads, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>());
        try {
            for (String candidate : candidates) {
                if (stopping) break;
                pool.execute(() -> probe(candidate));
            }
            pool.shutdown();
            try { pool.awaitTermination(1, TimeUnit.DAYS); }
            catch (InterruptedException e) { /* interrupted — fall through */ }
        } finally {
            if (reporter != null) reporter.onFinish(sent.get(), hits.size());
        }
    }

    /** Visible for tests: drive a single probe without spinning up the pool. */
    void probe(String candidate) {
        if (stopping || candidate == null || candidate.isEmpty()) return;
        ResponseInfo info;
        try { info = sender.sendGet(candidate); }
        catch (RuntimeException e) { info = ResponseInfo.ERROR; }
        if (info == null) info = ResponseInfo.ERROR;
        sent.incrementAndGet();
        boolean hit = successCodes.contains(info.status);
        if (hit) hits.add(new Hit(candidate, info.status, info.length));
        if (reporter != null) {
            try { reporter.onAttempt(candidate, info.status, info.length, hit); }
            catch (RuntimeException ignored) {}
        }
    }

    /** Parse a comma-separated status code list, falling back to defaults. */
    public static Set<Integer> parseCodes(String csv) {
        if (csv == null || csv.isBlank()) return DEFAULT_SUCCESS_CODES;
        Set<Integer> out = new java.util.LinkedHashSet<>();
        for (String token : csv.split(",")) {
            try { out.add(Integer.parseInt(token.trim())); }
            catch (NumberFormatException ignored) {}
        }
        return out.isEmpty() ? DEFAULT_SUCCESS_CODES : out;
    }
}
