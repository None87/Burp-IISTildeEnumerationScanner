package burp;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class PathFuzzerTest {

    /** Status-only canned sender (length stays -1). */
    private static PathFuzzer.RequestSender canned(Map<String, Integer> statusByCandidate) {
        return c -> PathFuzzer.ResponseInfo.statusOnly(statusByCandidate.getOrDefault(c, 404));
    }

    /** Canned sender that also returns explicit body lengths. */
    private static PathFuzzer.RequestSender cannedWithLengths(Map<String, int[]> table) {
        return c -> {
            int[] v = table.getOrDefault(c, new int[]{404, -1});
            return new PathFuzzer.ResponseInfo(v[0], v[1]);
        };
    }

    @Test
    void records_hits_for_configured_success_codes_only() throws Exception {
        Map<String, Integer> responses = new HashMap<>();
        responses.put("login.asp", 200);
        responses.put("admin.aspx", 301);
        responses.put("backup.zip", 403);
        responses.put("missing.html", 404);
        responses.put("error.aspx", 500);

        PathFuzzer fuzzer = new PathFuzzer(
                List.of("login.asp", "admin.aspx", "backup.zip", "missing.html", "error.aspx"),
                canned(responses),
                PathFuzzer.DEFAULT_SUCCESS_CODES,
                1, null);
        fuzzer.start();
        fuzzer.join();

        assertThat(fuzzer.sentCount()).isEqualTo(5);
        assertThat(fuzzer.getHits()).extracting(h -> h.candidate)
                .containsExactlyInAnyOrder("login.asp", "admin.aspx", "backup.zip");
        assertThat(fuzzer.getHits()).extracting(h -> h.statusCode)
                .containsExactlyInAnyOrder(200, 301, 403);
    }

    @Test
    void hits_capture_body_length_from_sender() throws Exception {
        Map<String, int[]> table = new HashMap<>();
        table.put("home.html", new int[]{200, 4321});
        table.put("backup.zip", new int[]{403, 145});
        table.put("missing.html", new int[]{404, 311});

        PathFuzzer fuzzer = new PathFuzzer(
                List.of("home.html", "backup.zip", "missing.html"),
                cannedWithLengths(table),
                PathFuzzer.DEFAULT_SUCCESS_CODES,
                1, null);
        fuzzer.start();
        fuzzer.join();

        assertThat(fuzzer.getHits()).extracting(h -> h.length)
                .containsExactlyInAnyOrder(4321, 145);
    }

    @Test
    void custom_success_code_set_overrides_default() throws Exception {
        Map<String, Integer> responses = Map.of(
                "a", 200,
                "b", 418,
                "c", 401);

        PathFuzzer fuzzer = new PathFuzzer(
                List.of("a", "b", "c"),
                canned(responses),
                Set.of(418),
                1, null);
        fuzzer.start();
        fuzzer.join();

        assertThat(fuzzer.getHits()).extracting(h -> h.candidate).containsExactly("b");
    }

    @Test
    void progress_reporter_fires_per_attempt_and_once_on_finish() throws Exception {
        Map<String, Integer> responses = Map.of("a", 200, "b", 404);

        AtomicInteger attempts = new AtomicInteger();
        AtomicInteger finishes = new AtomicInteger();
        int[] lastLength = {-99};
        int[] finalSent = {-1};
        int[] finalHits = {-1};

        PathFuzzer fuzzer = new PathFuzzer(
                List.of("a", "b"),
                canned(responses),
                PathFuzzer.DEFAULT_SUCCESS_CODES,
                1,
                new PathFuzzer.ProgressReporter() {
                    @Override public void onAttempt(String c, int s, int len, boolean hit) {
                        attempts.incrementAndGet();
                        lastLength[0] = len;
                    }
                    @Override public void onFinish(int sent, int hits) {
                        finishes.incrementAndGet();
                        finalSent[0] = sent;
                        finalHits[0] = hits;
                    }
                });
        fuzzer.start();
        fuzzer.join();

        assertThat(attempts.get()).isEqualTo(2);
        assertThat(finishes.get()).isEqualTo(1);
        assertThat(finalSent[0]).isEqualTo(2);
        assertThat(finalHits[0]).isEqualTo(1);
        assertThat(lastLength[0]).isEqualTo(-1); // canned() helper sets length=-1
    }

    @Test
    void deduplicates_candidate_list_before_sending() throws Exception {
        ConcurrentHashMap<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        PathFuzzer.RequestSender counting = c -> {
            calls.computeIfAbsent(c, k -> new AtomicInteger()).incrementAndGet();
            return PathFuzzer.ResponseInfo.statusOnly(200);
        };

        PathFuzzer fuzzer = new PathFuzzer(
                List.of("a", "a", "b", "a", "b"),
                counting,
                PathFuzzer.DEFAULT_SUCCESS_CODES,
                1, null);
        fuzzer.start();
        fuzzer.join();

        assertThat(fuzzer.candidateCount()).isEqualTo(2);
        assertThat(fuzzer.sentCount()).isEqualTo(2);
        assertThat(calls.get("a").get()).isEqualTo(1);
        assertThat(calls.get("b").get()).isEqualTo(1);
    }

    @Test
    void empty_candidate_list_finishes_immediately_with_zero_hits() throws Exception {
        AtomicInteger finishes = new AtomicInteger();
        PathFuzzer fuzzer = new PathFuzzer(
                List.of(),
                c -> PathFuzzer.ResponseInfo.statusOnly(200),
                PathFuzzer.DEFAULT_SUCCESS_CODES,
                4,
                new PathFuzzer.ProgressReporter() {
                    @Override public void onAttempt(String c, int s, int len, boolean h) {}
                    @Override public void onFinish(int sent, int hits) { finishes.incrementAndGet(); }
                });
        fuzzer.start();
        fuzzer.join();

        assertThat(fuzzer.sentCount()).isZero();
        assertThat(fuzzer.getHits()).isEmpty();
        assertThat(finishes.get()).isEqualTo(1);
    }

    @Test
    void sender_throwing_does_not_kill_fuzzer() throws Exception {
        PathFuzzer.RequestSender flaky = c -> {
            if (c.equals("b")) throw new RuntimeException("boom");
            return PathFuzzer.ResponseInfo.statusOnly(200);
        };

        PathFuzzer fuzzer = new PathFuzzer(
                List.of("a", "b", "c"),
                flaky,
                PathFuzzer.DEFAULT_SUCCESS_CODES,
                1, null);
        fuzzer.start();
        fuzzer.join();

        assertThat(fuzzer.sentCount()).isEqualTo(3);
        assertThat(fuzzer.getHits()).extracting(h -> h.candidate).containsExactlyInAnyOrder("a", "c");
    }

    @Test
    void parseCodes_handles_csv_whitespace_and_falls_back_to_default() {
        assertThat(PathFuzzer.parseCodes("200, 301 ,404"))
                .containsExactlyInAnyOrder(200, 301, 404);
        assertThat(PathFuzzer.parseCodes("")).isEqualTo(PathFuzzer.DEFAULT_SUCCESS_CODES);
        assertThat(PathFuzzer.parseCodes(null)).isEqualTo(PathFuzzer.DEFAULT_SUCCESS_CODES);
        assertThat(PathFuzzer.parseCodes("not a number"))
                .isEqualTo(PathFuzzer.DEFAULT_SUCCESS_CODES);
    }

    @Test
    void parallel_execution_completes_all_candidates() throws Exception {
        Map<String, Integer> table = new HashMap<>();
        for (int i = 0; i < 200; i++) table.put("c" + i, i % 3 == 0 ? 200 : 404);

        PathFuzzer fuzzer = new PathFuzzer(
                new java.util.ArrayList<>(table.keySet()),
                canned(table),
                PathFuzzer.DEFAULT_SUCCESS_CODES,
                8, null);
        fuzzer.start();
        fuzzer.join();

        assertThat(fuzzer.sentCount()).isEqualTo(200);
        long expectedHits = table.values().stream().filter(v -> v == 200).count();
        assertThat(fuzzer.getHits()).hasSize((int) expectedHits);
    }
}
