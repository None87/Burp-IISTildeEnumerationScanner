package burp;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

/**
 * Renders the "Status" column of the Fuzz Hits table with one colour per
 * HTTP class so an analyst can scan a long hit list at a glance:
 *
 * <ul>
 *   <li>2xx → green (clearly served)</li>
 *   <li>3xx → blue (redirect — often interesting)</li>
 *   <li>401 / 403 → amber (auth wall — high-value)</li>
 *   <li>4xx (other) → grey (probably noise)</li>
 *   <li>5xx → red (server choked, sometimes useful as a signal)</li>
 *   <li>anything else / -1 → muted grey</li>
 * </ul>
 */
public final class StatusCodeCellRenderer extends DefaultTableCellRenderer {

    private static final Color C_SUCCESS = new Color(46, 160, 67);
    private static final Color C_REDIRECT = new Color(43, 124, 224);
    private static final Color C_AUTH = new Color(217, 119, 6);
    private static final Color C_CLIENT = new Color(110, 110, 110);
    private static final Color C_SERVER = new Color(218, 54, 51);
    private static final Color C_OTHER = new Color(140, 140, 140);

    public StatusCodeCellRenderer() {
        setHorizontalAlignment(SwingConstants.CENTER);
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                    boolean hasFocus, int row, int column) {
        JLabel label = (JLabel) super.getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column);
        if (value instanceof Integer status) {
            label.setText(String.valueOf(status));
            label.setFont(label.getFont().deriveFont(Font.BOLD));
            if (!isSelected) label.setForeground(colorFor(status));
        }
        return label;
    }

    /** Visible for tests. */
    public static Color colorFor(int status) {
        if (status >= 200 && status < 300) return C_SUCCESS;
        if (status >= 300 && status < 400) return C_REDIRECT;
        if (status == 401 || status == 403) return C_AUTH;
        if (status >= 400 && status < 500) return C_CLIENT;
        if (status >= 500 && status < 600) return C_SERVER;
        return C_OTHER;
    }
}
