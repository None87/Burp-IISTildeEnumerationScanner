package burp;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/**
 * Tiny layout helpers so the giant {@code GridLayout(31,1)} block in
 * {@link BurpExtender} can be replaced with bordered, labeled sections that
 * line up properly. Pure UI plumbing — no Burp-API dependencies.
 */
public final class UiBuilders {

    private static final Color TITLE_COLOR = new Color(249, 130, 11);
    private static final Font TITLE_FONT = new Font("Nimbus", Font.BOLD, 13);

    private UiBuilders() {}

    /** A {@link JPanel} with {@link GridBagLayout} and an orange titled border. */
    public static JPanel titledSection(String title) {
        JPanel p = new JPanel(new GridBagLayout());
        TitledBorder border = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(190, 190, 190)),
                title);
        border.setTitleColor(TITLE_COLOR);
        border.setTitleFont(TITLE_FONT);
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(6, 6, 6, 6),
                border));
        return p;
    }

    /** Append a {@code [label] [field]} row to a {@link GridBagLayout} panel. */
    public static void addLabeledRow(JPanel target, int row, String labelText, JComponent field) {
        GridBagConstraints gbcLabel = new GridBagConstraints();
        gbcLabel.gridx = 0;
        gbcLabel.gridy = row;
        gbcLabel.anchor = GridBagConstraints.WEST;
        gbcLabel.insets = new Insets(4, 6, 4, 8);

        GridBagConstraints gbcField = new GridBagConstraints();
        gbcField.gridx = 1;
        gbcField.gridy = row;
        gbcField.fill = GridBagConstraints.HORIZONTAL;
        gbcField.weightx = 1.0;
        gbcField.insets = new Insets(4, 0, 4, 6);

        JLabel label = new JLabel(labelText);
        target.add(label, gbcLabel);
        target.add(field, gbcField);
    }

    /** Span a single component across both columns of a labeled section. */
    public static void addFullRow(JPanel target, int row, JComponent component) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(4, 6, 4, 6);
        target.add(component, gbc);
    }
}
