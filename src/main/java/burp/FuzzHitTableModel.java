package burp;

import javax.swing.table.AbstractTableModel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Table-model backing the new "Fuzz Hits" tab. Each row is a successful
 * candidate request: status code, full URL, body length (if known), and
 * timestamp.
 */
public final class FuzzHitTableModel extends AbstractTableModel {

    public static final int COL_STATUS = 0;
    public static final int COL_URL = 1;
    public static final int COL_LENGTH = 2;
    public static final int COL_TIME = 3;
    static final String[] COLUMNS = {"Status", "URL", "Length", "Time"};

    public static final class Row {
        public final int status;
        public final String url;
        public final int length;
        public final long timestampMs;

        public Row(int status, String url, int length, long timestampMs) {
            this.status = status;
            this.url = url;
            this.length = length;
            this.timestampMs = timestampMs;
        }
    }

    private final SimpleDateFormat fmt;
    private final List<Row> rows = new ArrayList<>();

    public FuzzHitTableModel() {
        this.fmt = new SimpleDateFormat("HH:mm:ss", Locale.ROOT);
        this.fmt.setTimeZone(TimeZone.getDefault());
    }

    public void append(Row row) {
        if (row == null) return;
        rows.add(row);
        int idx = rows.size() - 1;
        fireTableRowsInserted(idx, idx);
    }

    public Row rowAt(int modelIndex) {
        if (modelIndex < 0 || modelIndex >= rows.size()) return null;
        return rows.get(modelIndex);
    }

    public List<Row> snapshot() { return new ArrayList<>(rows); }

    public void clear() {
        rows.clear();
        fireTableDataChanged();
    }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int column) { return COLUMNS[column]; }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return switch (columnIndex) {
            case COL_STATUS, COL_LENGTH -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Row r = rows.get(rowIndex);
        return switch (columnIndex) {
            case COL_STATUS -> r.status;
            case COL_URL -> r.url;
            case COL_LENGTH -> r.length;
            case COL_TIME -> fmt.format(new Date(r.timestampMs));
            default -> "";
        };
    }
}
