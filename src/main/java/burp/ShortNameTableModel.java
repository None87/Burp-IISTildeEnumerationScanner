package burp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Table-model backing the Scanner tab's "Discovered Short Names" panel.
 * Append-only on the EDT; the scanner UI tracks a {@link Set} of already-seen
 * keys via {@link #seenKeys} to avoid duplicating rows when the bruteforcer
 * is polled on a timer.
 */
public final class ShortNameTableModel extends AbstractTableModel {

    public static final int COL_TYPE = 0;
    public static final int COL_NAME = 1;
    static final String[] COLUMNS = {"Type", "Short Name"};

    public static final class Row {
        public final String type;   // "File" or "Dir"
        public final String name;   // raw short name, e.g. "LOGIN~1.ASP"

        public Row(String type, String name) {
            this.type = type;
            this.name = name;
        }

        public String key() { return type + "|" + name; }
    }

    private final List<Row> rows = new ArrayList<>();
    private final Set<String> seenKeys = new HashSet<>();

    /** Append one row. Returns true if the row was new, false if it was a duplicate. */
    public boolean append(Row row) {
        if (row == null || !seenKeys.add(row.key())) return false;
        rows.add(row);
        int idx = rows.size() - 1;
        fireTableRowsInserted(idx, idx);
        return true;
    }

    public Row rowAt(int modelIndex) {
        if (modelIndex < 0 || modelIndex >= rows.size()) return null;
        return rows.get(modelIndex);
    }

    public void clear() {
        rows.clear();
        seenKeys.clear();
        fireTableDataChanged();
    }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int column) { return COLUMNS[column]; }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Row r = rows.get(rowIndex);
        return switch (columnIndex) {
            case COL_TYPE -> r.type;
            case COL_NAME -> r.name;
            default -> "";
        };
    }
}
