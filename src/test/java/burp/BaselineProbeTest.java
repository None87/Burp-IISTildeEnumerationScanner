package burp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BaselineProbeTest {

    @Test
    void classifies_404_as_expected() {
        assertThat(BaselineProbe.classify(404)).isEqualTo(BaselineProbe.Verdict.EXPECTED_404);
    }

    @Test
    void classifies_200_as_suspicious() {
        // Custom error page / SPA — body diff will be unreliable.
        assertThat(BaselineProbe.classify(200)).isEqualTo(BaselineProbe.Verdict.SUSPICIOUS_200);
    }

    @Test
    void classifies_3xx_as_redirect() {
        assertThat(BaselineProbe.classify(301)).isEqualTo(BaselineProbe.Verdict.REDIRECT);
        assertThat(BaselineProbe.classify(302)).isEqualTo(BaselineProbe.Verdict.REDIRECT);
        assertThat(BaselineProbe.classify(307)).isEqualTo(BaselineProbe.Verdict.REDIRECT);
    }

    @Test
    void classifies_401_and_403_as_auth_wall() {
        assertThat(BaselineProbe.classify(401)).isEqualTo(BaselineProbe.Verdict.AUTH_WALL);
        assertThat(BaselineProbe.classify(403)).isEqualTo(BaselineProbe.Verdict.AUTH_WALL);
        // 404 itself stays in EXPECTED_404 even though it's a 4xx
        assertThat(BaselineProbe.classify(404)).isNotEqualTo(BaselineProbe.Verdict.AUTH_WALL);
    }

    @Test
    void classifies_5xx_as_server_error() {
        assertThat(BaselineProbe.classify(500)).isEqualTo(BaselineProbe.Verdict.SERVER_ERROR);
        assertThat(BaselineProbe.classify(503)).isEqualTo(BaselineProbe.Verdict.SERVER_ERROR);
        assertThat(BaselineProbe.classify(599)).isEqualTo(BaselineProbe.Verdict.SERVER_ERROR);
    }

    @Test
    void other_codes_classified_as_unknown() {
        assertThat(BaselineProbe.classify(412)).isEqualTo(BaselineProbe.Verdict.UNKNOWN);
        assertThat(BaselineProbe.classify(-1)).isEqualTo(BaselineProbe.Verdict.UNKNOWN);
        assertThat(BaselineProbe.classify(0)).isEqualTo(BaselineProbe.Verdict.UNKNOWN);
    }

    @Test
    void expected_404_message_is_empty_so_log_stays_clean() {
        BaselineProbe.Result r = BaselineProbe.build(404, "abc.htm");
        assertThat(r.message()).isEmpty();
    }

    @Test
    void suspicious_200_message_calls_out_custom_error_page() {
        BaselineProbe.Result r = BaselineProbe.build(200, "abc.htm");
        assertThat(r.message())
                .contains("[!] WARNING")
                .contains("200")
                .contains("custom error page")
                .contains("abc.htm");
    }

    @Test
    void auth_wall_message_suggests_authentication() {
        BaselineProbe.Result r = BaselineProbe.build(403, "abc.htm");
        assertThat(r.message()).contains("authenticating");
    }

    @Test
    void random_filename_is_13_chars_plus_htm() {
        String f = BaselineProbe.randomFilename();
        assertThat(f).endsWith(".htm");
        assertThat(f).hasSize(17);
        assertThat(f.replace(".htm", "")).matches("[A-Za-z0-9]{13}");
    }

    @Test
    void random_filename_changes_between_calls() {
        String a = BaselineProbe.randomFilename();
        String b = BaselineProbe.randomFilename();
        // 62^13 collision probability is negligible — two calls must differ.
        assertThat(a).isNotEqualTo(b);
    }
}
