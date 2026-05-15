package burp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UiWidgetsTest {

    @Test
    void colored_log_pane_picks_correct_style_per_prefix() {
        assertThat(ColoredLogPane.pickStyleFor("[+] HIT 200 /login.aspx")).isEqualTo("hit");
        assertThat(ColoredLogPane.pickStyleFor("[X] Connection error")).isEqualTo("error");
        assertThat(ColoredLogPane.pickStyleFor("[!] Stack trace")).isEqualTo("error");
        assertThat(ColoredLogPane.pickStyleFor("[*] Phase 1 starting")).isEqualTo("status");
        assertThat(ColoredLogPane.pickStyleFor("[i] File: LOGIN~1.ASP")).isEqualTo("default");
        assertThat(ColoredLogPane.pickStyleFor("plain line")).isEqualTo("default");
        assertThat(ColoredLogPane.pickStyleFor(null)).isEqualTo("default");
        assertThat(ColoredLogPane.pickStyleFor("")).isEqualTo("default");
    }

    @Test
    void short_name_table_dedups_on_append() {
        ShortNameTableModel m = new ShortNameTableModel();
        assertThat(m.append(new ShortNameTableModel.Row("File", "LOGIN~1.ASP"))).isTrue();
        assertThat(m.append(new ShortNameTableModel.Row("File", "LOGIN~1.ASP"))).isFalse();
        assertThat(m.append(new ShortNameTableModel.Row("Dir", "BACKUP~1"))).isTrue();
        assertThat(m.getRowCount()).isEqualTo(2);
    }

    @Test
    void short_name_table_null_row_safely_ignored() {
        ShortNameTableModel m = new ShortNameTableModel();
        assertThat(m.append(null)).isFalse();
        assertThat(m.getRowCount()).isZero();
    }

    @Test
    void short_name_table_clear_resets_dedup_set() {
        ShortNameTableModel m = new ShortNameTableModel();
        m.append(new ShortNameTableModel.Row("File", "A~1.ASP"));
        m.clear();
        // Same row should be accepted again because dedup set was cleared.
        assertThat(m.append(new ShortNameTableModel.Row("File", "A~1.ASP"))).isTrue();
    }

    @Test
    void fuzz_hit_table_columns_and_values() {
        FuzzHitTableModel m = new FuzzHitTableModel();
        m.append(new FuzzHitTableModel.Row(200, "https://x/login", 4321, 1_700_000_000_000L));
        m.append(new FuzzHitTableModel.Row(301, "https://x/admin", 312, 1_700_000_001_000L));

        assertThat(m.getRowCount()).isEqualTo(2);
        assertThat(m.getColumnCount()).isEqualTo(4);
        assertThat(m.getValueAt(0, FuzzHitTableModel.COL_STATUS)).isEqualTo(200);
        assertThat(m.getValueAt(0, FuzzHitTableModel.COL_URL)).isEqualTo("https://x/login");
        assertThat(m.getValueAt(1, FuzzHitTableModel.COL_LENGTH)).isEqualTo(312);

        assertThat(m.getColumnClass(FuzzHitTableModel.COL_STATUS)).isEqualTo(Integer.class);
        assertThat(m.getColumnClass(FuzzHitTableModel.COL_URL)).isEqualTo(String.class);
    }

    @Test
    void fuzz_hit_table_snapshot_isolated_from_subsequent_appends() {
        FuzzHitTableModel m = new FuzzHitTableModel();
        m.append(new FuzzHitTableModel.Row(200, "a", 1, 1L));
        var snap = m.snapshot();
        m.append(new FuzzHitTableModel.Row(404, "b", 2, 2L));
        assertThat(snap).hasSize(1);
        assertThat(m.getRowCount()).isEqualTo(2);
    }

    @Test
    void status_code_renderer_distinguishes_http_classes() {
        java.awt.Color s200 = StatusCodeCellRenderer.colorFor(200);
        java.awt.Color s301 = StatusCodeCellRenderer.colorFor(301);
        java.awt.Color s401 = StatusCodeCellRenderer.colorFor(401);
        java.awt.Color s403 = StatusCodeCellRenderer.colorFor(403);
        java.awt.Color s404 = StatusCodeCellRenderer.colorFor(404);
        java.awt.Color s500 = StatusCodeCellRenderer.colorFor(500);
        java.awt.Color sNeg = StatusCodeCellRenderer.colorFor(-1);

        // Each class gets a distinct colour
        assertThat(s200).isNotEqualTo(s301);
        assertThat(s200).isNotEqualTo(s401);
        assertThat(s200).isNotEqualTo(s404);
        assertThat(s200).isNotEqualTo(s500);
        // 401 and 403 share the "auth" colour, deliberately
        assertThat(s401).isEqualTo(s403);
        // 404 (other 4xx) is distinct from auth codes
        assertThat(s404).isNotEqualTo(s401);
        // Error sentinel falls into "other"
        assertThat(sNeg).isEqualTo(StatusCodeCellRenderer.colorFor(0));
    }
}
