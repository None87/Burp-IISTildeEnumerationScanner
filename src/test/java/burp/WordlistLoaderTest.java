package burp;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WordlistLoaderTest {

    @Test
    void loads_bundled_extensions_from_jar_resources() throws Exception {
        List<String> lines = WordlistLoader.load("bundled:extensions");
        assertThat(lines).isNotEmpty();
        // The Python-shipped extensions list contains the canonical web file
        // suffixes — sanity-check a few we expect.
        assertThat(lines).anyMatch(s -> s.equalsIgnoreCase("asp"));
        assertThat(lines).anyMatch(s -> s.equalsIgnoreCase("aspx"));
        assertThat(lines).anyMatch(s -> s.equalsIgnoreCase("php"));
    }

    @Test
    void loads_bundled_small_filename_list() {
        List<String> lines = WordlistLoader.load("bundled:small");
        assertThat(lines).isNotEmpty();
    }

    @Test
    void loads_external_file_path(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path f = tmp.resolve("custom.txt");
        Files.writeString(f, "alpha\nbeta\ngamma\n");
        List<String> lines = WordlistLoader.load(f.toString());
        assertThat(lines).containsExactly("alpha", "beta", "gamma");
    }

    @Test
    void empty_or_missing_source_returns_empty_list() {
        assertThat(WordlistLoader.load(null)).isEmpty();
        assertThat(WordlistLoader.load("")).isEmpty();
        assertThat(WordlistLoader.load("   ")).isEmpty();
        assertThat(WordlistLoader.load("/path/that/does/not/exist/whatever.txt")).isEmpty();
    }

    @Test
    void missing_bundled_name_returns_empty_without_throwing() {
        assertThat(WordlistLoader.load("bundled:does_not_exist")).isEmpty();
    }

    @Test
    void label_formats_distinguish_bundled_from_file() {
        assertThat(WordlistLoader.label("bundled:big")).isEqualTo("bundled:big");
        assertThat(WordlistLoader.label("/tmp/x.txt")).isEqualTo("file:/tmp/x.txt");
        assertThat(WordlistLoader.label("")).isEqualTo("(none)");
        assertThat(WordlistLoader.label(null)).isEqualTo("(none)");
    }
}
