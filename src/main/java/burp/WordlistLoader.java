package burp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Resolves wordlist sources for both bundled JAR resources and external files.
 *
 * <p>Bundled resources (shipped alongside the plugin):
 * <ul>
 *   <li>{@code bundled:big} — full ~10K word list, ported from {@code iis_tilde_enum/wordlists/big.txt}</li>
 *   <li>{@code bundled:small} — quick-scan list, a few hundred words</li>
 *   <li>{@code bundled:common} — curated common filenames</li>
 *   <li>{@code bundled:words_dictionary} — English dictionary words</li>
 *   <li>{@code bundled:extensions} — common web file extensions</li>
 *   <li>{@code bundled:extensions_ignore} — extensions to skip</li>
 * </ul>
 *
 * Any other value is treated as a filesystem path. Empty strings return an
 * empty list. The chosen-wordlist string round-trips through {@link Config}
 * and is what the UI persists.
 */
public final class WordlistLoader {

    public static final String BUNDLED_PREFIX = "bundled:";

    public static final List<String> BUNDLED_FILENAME_LISTS =
            Arrays.asList("bundled:big", "bundled:small", "bundled:common", "bundled:words_dictionary");
    public static final List<String> BUNDLED_EXTENSION_LISTS =
            Arrays.asList("bundled:extensions", "bundled:extensions_ignore");

    private WordlistLoader() {}

    /** Empty / null input returns an empty list (caller decides whether to error). */
    public static List<String> load(String source) {
        if (source == null || source.isBlank()) return new ArrayList<>();
        try {
            if (source.startsWith(BUNDLED_PREFIX)) {
                return loadBundled(source.substring(BUNDLED_PREFIX.length()));
            }
            Path path = Paths.get(source);
            if (Files.exists(path)) return Files.readAllLines(path, StandardCharsets.UTF_8);
            return new ArrayList<>();
        } catch (IOException e) {
            return new ArrayList<>();
        }
    }

    static List<String> loadBundled(String name) throws IOException {
        String resourcePath = "/wordlists/" + name + ".txt";
        try (InputStream in = WordlistLoader.class.getResourceAsStream(resourcePath)) {
            if (in == null) throw new IOException("bundled wordlist not found: " + resourcePath);
            List<String> lines = new ArrayList<>();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) lines.add(trimmed);
                }
            }
            return lines;
        }
    }

    /** Human label for the wordlist dropdown. */
    public static String label(String source) {
        if (source == null || source.isBlank()) return "(none)";
        if (source.startsWith(BUNDLED_PREFIX)) return source;
        return "file:" + source;
    }
}
