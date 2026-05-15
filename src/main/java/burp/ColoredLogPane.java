package burp;

import javax.swing.JTextPane;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;
import java.awt.Color;
import java.awt.Font;

/**
 * Drop-in replacement for the scanner's plain {@link JTextPane} that
 * recolors each line by its prefix marker:
 *
 * <ul>
 *   <li>{@code [+]} → green  (hit / success)</li>
 *   <li>{@code [X]} → red    (error / interruption)</li>
 *   <li>{@code [*]} → cyan   (phase status / progress)</li>
 *   <li>{@code [i]} → default fg (informational)</li>
 *   <li>everything else → default fg</li>
 * </ul>
 *
 * <p>The existing {@code Output} class writes via {@code setText(fullBuffer)};
 * we override {@link #setText} so the colouring pass kicks in for free
 * without touching the caller.
 */
public final class ColoredLogPane extends JTextPane {

    private static final String STYLE_HIT = "hit";
    private static final String STYLE_ERROR = "error";
    private static final String STYLE_STATUS = "status";
    private static final String STYLE_DEFAULT = "default";

    public ColoredLogPane() {
        setEditable(false);
        setFont(new Font("Monospaced", Font.PLAIN, 12));
        installStyles();
    }

    private void installStyles() {
        StyleContext sc = StyleContext.getDefaultStyleContext();
        Style baseDefault = sc.getStyle(StyleContext.DEFAULT_STYLE);

        Style def = addStyle(STYLE_DEFAULT, baseDefault);
        StyleConstants.setForeground(def, getForeground());

        Style hit = addStyle(STYLE_HIT, baseDefault);
        StyleConstants.setForeground(hit, new Color(46, 160, 67));
        StyleConstants.setBold(hit, true);

        Style err = addStyle(STYLE_ERROR, baseDefault);
        StyleConstants.setForeground(err, new Color(218, 54, 51));
        StyleConstants.setBold(err, true);

        Style status = addStyle(STYLE_STATUS, baseDefault);
        StyleConstants.setForeground(status, new Color(43, 124, 224));
    }

    @Override
    public void setText(String text) {
        super.setText(text);
        recolor();
    }

    /** Walk the document line by line and apply the style that matches each line's prefix. */
    void recolor() {
        StyledDocument doc = getStyledDocument();
        String content;
        try { content = doc.getText(0, doc.getLength()); }
        catch (Exception e) { return; }

        int offset = 0;
        for (String line : content.split("\n", -1)) {
            Style s = getStyle(pickStyleFor(line));
            if (s != null) {
                int len = Math.min(line.length(), doc.getLength() - offset);
                if (len > 0) doc.setCharacterAttributes(offset, len, s, true);
            }
            offset += line.length() + 1; // +1 for the newline
        }
    }

    /** Visible for tests. */
    static String pickStyleFor(String line) {
        if (line == null) return STYLE_DEFAULT;
        String trimmed = line.trim();
        if (trimmed.startsWith("[+]")) return STYLE_HIT;
        if (trimmed.startsWith("[X]") || trimmed.startsWith("[!]")) return STYLE_ERROR;
        if (trimmed.startsWith("[*]")) return STYLE_STATUS;
        return STYLE_DEFAULT;
    }
}
