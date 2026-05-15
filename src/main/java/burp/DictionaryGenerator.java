package burp;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java port of {@code generateMatches} + {@code generateDictionaryFromFindings}
 * from the upstream Python {@code tilde_enum.py}. Produces a flat candidate
 * wordlist from discovered IIS 8.3 short names — suitable for piping to
 * {@code ffuf} / {@code feroxbuster} / {@code gobuster}.
 *
 * <p>Two-phase generation, matching upstream:
 * <ol>
 *   <li><b>Phase 1 (high priority)</b>: every dictionary word that
 *       <i>starts with</i> the short-name prefix, cross-joined with every
 *       extension that starts with the short extension.</li>
 *   <li><b>Phase 2 (tildeGuess, opt-in)</b>: reverse-search — for every
 *       suffix of the short name, find dictionary entries that begin with
 *       that suffix and rebuild full candidates by stitching the unmatched
 *       prefix back on.</li>
 * </ol>
 *
 * <p>Insertion order is preserved so Phase 1 candidates appear first when
 * the wordlist is consumed by another fuzzer.
 */
public final class DictionaryGenerator {

    /** What gets fed in from the bruteforce results / Sitemap / etc. */
    public static final class ShortName {
        public final String name;     // e.g. "LOGIN~1.ASP" or "ADMIN~1/"
        public final boolean isFile;

        public ShortName(String name, boolean isFile) {
            this.name = name;
            this.isFile = isFile;
        }

        /** Parse a {@code Bruteforcer} output line like "LOGIN~1.ASP" or "BACKUP~1". */
        public static ShortName parse(String raw) {
            if (raw == null || raw.isBlank()) return null;
            String s = raw.trim();
            boolean isFile = !s.endsWith("/");
            if (!isFile) s = s.substring(0, s.length() - 1);
            return new ShortName(s.toUpperCase(Locale.ROOT), isFile);
        }
    }

    private DictionaryGenerator() {}

    /**
     * Convert a {@link Bruteforcer}'s {@code filesFound} / {@code dirsFound}
     * lists into {@link ShortName} records the generator can consume. Skips
     * placeholder entries containing {@code ?} (unfinished or unknown
     * extension cases produced by the bruteforcer's error handling) since
     * they don't yield usable dictionary candidates.
     */
    public static List<ShortName> fromBruteforcerResults(List<String> filesFound, List<String> dirsFound) {
        List<ShortName> out = new java.util.ArrayList<>();
        if (dirsFound != null) {
            for (String d : dirsFound) {
                if (d == null || d.isBlank() || d.contains("?")) continue;
                out.add(new ShortName(d.toUpperCase(Locale.ROOT), false));
            }
        }
        if (filesFound != null) {
            for (String f : filesFound) {
                if (f == null || f.isBlank() || f.contains("?")) continue;
                out.add(new ShortName(f.toUpperCase(Locale.ROOT), true));
            }
        }
        return out;
    }

    /**
     * Generate the complete candidate wordlist for a batch of short names.
     *
     * @param shortNames     parsed discovery results
     * @param dictionary     filename wordlist (lowercase preferred)
     * @param extensions     extension wordlist
     * @param enableTildeGuess  run Phase 2 in addition to Phase 1
     */
    public static List<String> generate(List<ShortName> shortNames,
                                        List<String> dictionary,
                                        List<String> extensions,
                                        boolean enableTildeGuess) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (shortNames == null) return new ArrayList<>(out);

        for (ShortName sn : shortNames) {
            if (sn == null || sn.name == null || sn.name.isEmpty()) continue;
            out.addAll(generateForOne(sn, dictionary, extensions, enableTildeGuess));
        }
        return new ArrayList<>(out);
    }

    static List<String> generateForOne(ShortName sn,
                                       List<String> dictionary,
                                       List<String> extensions,
                                       boolean enableTildeGuess) {
        LinkedHashSet<String> matches = new LinkedHashSet<>();

        String filename;
        String ext = "";
        if (sn.isFile) {
            int dot = sn.name.lastIndexOf('.');
            if (dot < 0) return new ArrayList<>(matches);
            filename = sn.name.substring(0, dot);
            ext = sn.name.substring(dot + 1);
        } else {
            filename = sn.name;
        }

        // Skip non-first variants — only generate for the canonical ~1 form
        // (matches upstream Python's `if filename[-1] != '1': continue`).
        if (filename.isEmpty() || filename.charAt(filename.length() - 1) != '1') {
            return new ArrayList<>(matches);
        }

        // Strip the "~1" suffix: "LOGIN~1" → "LOGIN".
        int tilde = filename.lastIndexOf('~');
        if (tilde < 0) return new ArrayList<>(matches);
        String prefix = filename.substring(0, tilde).toLowerCase(Locale.ROOT);

        // possibleExts = every extension wordlist entry that starts with the
        // short extension; plus the short extension itself (matching upstream).
        List<String> possibleExts = new ArrayList<>();
        if (sn.isFile) {
            String shortExt = ext.toLowerCase(Locale.ROOT);
            if (extensions != null) {
                for (String e : extensions) {
                    if (e == null) continue;
                    String low = e.trim().toLowerCase(Locale.ROOT);
                    if (low.isEmpty() || low.equals(shortExt)) continue;
                    if (low.startsWith(shortExt)) possibleExts.add(low);
                }
            }
            possibleExts.add(shortExt);
        }

        // Phase 1: high-priority matches — words that start with the prefix.
        List<String> startsWith = new ArrayList<>();
        if (dictionary != null) {
            for (String w : dictionary) {
                if (w == null) continue;
                String low = w.toLowerCase(Locale.ROOT);
                if (low.isEmpty() || low.equals(prefix)) continue;
                if (low.startsWith(prefix)) startsWith.add(low);
            }
        }
        startsWith.add(prefix);

        if (sn.isFile) {
            for (String w : startsWith) {
                for (String e : possibleExts) {
                    matches.add(w + "." + e);
                }
            }
        } else {
            matches.addAll(startsWith);
        }

        // Phase 2: tildeGuess reverse-search.
        if (enableTildeGuess) {
            List<String> reverse = generateMatches(prefix, dictionary);
            if (sn.isFile) {
                for (String r : reverse) {
                    for (String e : possibleExts) {
                        matches.add(r + "." + e);
                    }
                }
            } else {
                matches.addAll(reverse);
            }
        }

        return new ArrayList<>(matches);
    }

    /**
     * Reverse-search dictionary match — direct Java port of the Python
     * {@code generateMatches(input_word, dictionary)} function.
     *
     * <p>Walks the input word right-to-left, accumulating a suffix. For each
     * suffix, every dictionary entry that starts with that suffix produces a
     * candidate built as {@code input_word[0 : rfind(suffix)] + match}.
     */
    public static List<String> generateMatches(String inputWord, List<String> dictionary) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (inputWord == null || inputWord.isEmpty() || dictionary == null || dictionary.isEmpty()) {
            return new ArrayList<>(out);
        }
        String lower = inputWord.toLowerCase(Locale.ROOT);
        StringBuilder dism = new StringBuilder();
        for (int i = lower.length() - 1; i >= 0; i--) {
            dism.insert(0, lower.charAt(i));
            String suffix = dism.toString();
            int splitAt = lower.lastIndexOf(suffix);
            String pfx = splitAt >= 0 ? lower.substring(0, splitAt) : "";
            Pattern p;
            try {
                p = Pattern.compile("^" + Pattern.quote(suffix) + ".*",
                        Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
            } catch (RuntimeException e) {
                continue;
            }
            for (String entry : dictionary) {
                if (entry == null) continue;
                String trimmed = entry.trim();
                if (trimmed.isEmpty()) continue;
                Matcher m = p.matcher(trimmed);
                if (m.matches()) {
                    out.add((pfx + trimmed).toLowerCase(Locale.ROOT));
                }
            }
        }
        return new ArrayList<>(out);
    }
}
