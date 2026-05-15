package burp;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DictionaryGeneratorTest {

    @Test
    void parses_file_short_name_with_extension() {
        DictionaryGenerator.ShortName sn = DictionaryGenerator.ShortName.parse("LOGIN~1.ASP");
        assertThat(sn).isNotNull();
        assertThat(sn.isFile).isTrue();
        assertThat(sn.name).isEqualTo("LOGIN~1.ASP");
    }

    @Test
    void parses_directory_trailing_slash() {
        DictionaryGenerator.ShortName sn = DictionaryGenerator.ShortName.parse("backup~1/");
        assertThat(sn).isNotNull();
        assertThat(sn.isFile).isFalse();
        assertThat(sn.name).isEqualTo("BACKUP~1");
    }

    @Test
    void phase1_high_priority_starts_with_prefix_cross_extensions() {
        List<DictionaryGenerator.ShortName> inputs = List.of(
                DictionaryGenerator.ShortName.parse("LOGIN~1.ASP"));
        List<String> dict = Arrays.asList("login", "loginPage", "logout", "longshot");
        // "aspx" starts with "asp"; "asmx" does not (matching upstream Python's str.startswith).
        List<String> exts = Arrays.asList("asp", "aspx", "asmx", "php");

        List<String> generated = DictionaryGenerator.generate(inputs, dict, exts, false);

        // Words that start with "login" × extensions that start with "asp" (= aspx, plus literal asp).
        assertThat(generated).contains(
                "login.asp", "login.aspx",
                "loginpage.asp", "loginpage.aspx");
        // Extensions that DON'T start with the short ext are excluded.
        assertThat(generated).noneMatch(s -> s.endsWith(".asmx"));
        assertThat(generated).noneMatch(s -> s.endsWith(".php"));
        // Words that don't share the prefix are excluded.
        assertThat(generated).noneMatch(s -> s.startsWith("logout."));
        assertThat(generated).noneMatch(s -> s.startsWith("longshot."));
    }

    @Test
    void skips_non_first_short_name_variants() {
        // ~2 / ~3 are duplicates that share the same short name as ~1; upstream
        // skips them to avoid the same prefix being generated multiple times.
        List<DictionaryGenerator.ShortName> inputs = List.of(
                DictionaryGenerator.ShortName.parse("LOGIN~2.ASP"));
        List<String> dict = List.of("login");
        List<String> exts = List.of("asp");

        List<String> generated = DictionaryGenerator.generate(inputs, dict, exts, true);
        assertThat(generated).isEmpty();
    }

    @Test
    void directory_short_name_emits_words_without_extension() {
        List<DictionaryGenerator.ShortName> inputs = List.of(
                DictionaryGenerator.ShortName.parse("ADMIN~1/"));
        List<String> dict = Arrays.asList("admin", "administration", "adminpanel", "other");

        List<String> generated = DictionaryGenerator.generate(inputs, dict, List.of(), false);

        assertThat(generated).contains("admin", "administration", "adminpanel");
        assertThat(generated).doesNotContain("other");
        assertThat(generated).noneMatch(s -> s.contains("."));
    }

    @Test
    void tilde_guess_reverse_search_recovers_dictionary_words_by_suffix() {
        // Even if the dictionary has no word starting with the full prefix,
        // the reverse-search picks entries that begin with some suffix.
        List<String> dict = Arrays.asList("rangers", "gerbera", "germany");
        List<String> matches = DictionaryGenerator.generateMatches("danger", dict);

        // "danger" reverse-walk hits suffix "r" → entry "rangers" → candidate "dangerangers"? No:
        // candidate = inputWord[0 : rfind("r")] + match = "dange" + "rangers" = "dangerangers".
        // Suffix "ger" → entry "gerbera" → candidate = "dan" + "gerbera" = "dangerbera".
        // Suffix "ger" → entry "germany" → candidate = "dan" + "germany" = "dangermany".
        assertThat(matches).contains("dangerangers", "dangerbera", "dangermany");
    }

    @Test
    void tilde_guess_phase2_only_runs_when_flag_enabled() {
        List<DictionaryGenerator.ShortName> inputs = List.of(
                DictionaryGenerator.ShortName.parse("LOGIN~1.ASP"));
        // Dictionary contains nothing that starts with "login" — so Phase 1
        // yields only "login.asp" itself. Phase 2 would find suffix matches.
        List<String> dict = Arrays.asList("admin", "page", "form");
        List<String> exts = List.of("asp");

        List<String> withoutGuess = DictionaryGenerator.generate(inputs, dict, exts, false);
        List<String> withGuess = DictionaryGenerator.generate(inputs, dict, exts, true);

        assertThat(withoutGuess).containsExactly("login.asp");
        assertThat(withGuess).contains("login.asp");
        assertThat(withGuess.size()).isGreaterThanOrEqualTo(withoutGuess.size());
    }

    @Test
    void output_preserves_phase1_first_then_phase2() {
        List<DictionaryGenerator.ShortName> inputs = List.of(
                DictionaryGenerator.ShortName.parse("LOGIN~1.ASP"));
        List<String> dict = Arrays.asList("login", "loginpage", "rangers");
        List<String> exts = List.of("asp");

        List<String> generated = DictionaryGenerator.generate(inputs, dict, exts, true);

        // Phase 1 entries must appear before any Phase 2 entries.
        int phase1Last = Math.max(generated.indexOf("login.asp"), generated.indexOf("loginpage.asp"));
        int phase2First = generated.indexOf("loginrangers.asp"); // built by reverse-search on suffix "n" -> "rangers"? unclear -- just check phase 1 came first
        // Simpler invariant: phase1 entries are at the top
        assertThat(generated.subList(0, 2)).contains("login.asp", "loginpage.asp");
    }

    @Test
    void null_or_empty_inputs_return_empty_list() {
        assertThat(DictionaryGenerator.generate(null, List.of("x"), List.of("a"), false)).isEmpty();
        assertThat(DictionaryGenerator.generate(List.of(), List.of("x"), List.of("a"), false)).isEmpty();
        assertThat(DictionaryGenerator.generateMatches(null, List.of("x"))).isEmpty();
        assertThat(DictionaryGenerator.generateMatches("", List.of("x"))).isEmpty();
        assertThat(DictionaryGenerator.generateMatches("login", null)).isEmpty();
    }
}
