package burp;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.List;

/**
 * Composite widget: an editable {@link JComboBox} pre-populated with the
 * bundled wordlist identifiers, plus a "Browse…" button that lets the user
 * pick an arbitrary file path. The combo's text value is the wordlist
 * source string consumed by {@link WordlistLoader}.
 */
public final class WordlistPicker extends JPanel {

    private final JComboBox<String> combo;
    private final JButton browse;

    public WordlistPicker(List<String> bundledOptions, String defaultSource) {
        super(new BorderLayout(6, 0));
        this.combo = new JComboBox<>(bundledOptions.toArray(new String[0]));
        combo.setEditable(true);
        if (defaultSource != null && !defaultSource.isEmpty()) {
            combo.setSelectedItem(defaultSource);
        }
        add(combo, BorderLayout.CENTER);

        this.browse = new JButton("Browse…");
        browse.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Choose wordlist file");
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                String path = fc.getSelectedFile().getAbsolutePath();
                if (((javax.swing.DefaultComboBoxModel<String>) combo.getModel()).getIndexOf(path) < 0) {
                    combo.addItem(path);
                }
                combo.setSelectedItem(path);
            }
        });
        add(browse, BorderLayout.EAST);

        setMaximumSize(new Dimension(Integer.MAX_VALUE, getPreferredSize().height));
    }

    /** Trimmed source string ({@code bundled:NAME} or filesystem path), never null. */
    public String getSelected() {
        Object v = combo.getEditor().getItem();
        if (v == null) v = combo.getSelectedItem();
        return v == null ? "" : v.toString().trim();
    }

    public void setSelected(String value) {
        if (value != null) combo.setSelectedItem(value);
    }
}
