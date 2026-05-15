package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JToolBar;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

public class BurpExtender implements IBurpExtender, ITab {

    private static final String NAME = "IIS Tilde Enumeration Scanner";
    private static final String VERSION = "3.0";
    private static final String AUTHOR = "cyberaz0r (orig) + iis_tilde_enum merge by 0xhusky";
    private static final Color ACCENT = new Color(249, 130, 11);
    private static final Color SCAN_GREEN = new Color(46, 160, 67);

    private IBurpExtenderCallbacks callbacks;
    private JTabbedPane mainUI;

    // toolbar widgets (shared state across tabs/handlers)
    private JTextField targetUrlField;
    private JTextField nThreadsField;
    private JButton scanButton;
    private JButton fuzzButton;
    private JLabel statusLabel;
    private JProgressBar progressBar;

    // request editor + log + tables
    private JTextPane requestEditor;
    private ColoredLogPane logPane;
    private final ShortNameTableModel shortNameModel = new ShortNameTableModel();
    private final FuzzHitTableModel fuzzHitModel = new FuzzHitTableModel();
    private JTable shortNameTable;
    private JTable fuzzHitTable;
    private TableRowSorter<FuzzHitTableModel> fuzzSorter;
    private JTextField fuzzFilterField;
    private int fuzzHitsTabIndex = -1;

    // backing config widgets
    private final HashMap<String, JTextField> confFields = new HashMap<>();
    private JCheckBox exploitModeCheckbox;
    private JCheckBox completeFileGuessSitemapCheckbox;
    private JCheckBox completeFileGuessWordlistCheckbox;
    private JCheckBox tildeGuessCheckbox;
    private WordlistPicker fileNamePicker;
    private WordlistPicker fileExtPicker;

    // running threads
    private TildeEnumerationScanner tildeEnumerationScanner;
    private PathFuzzer pathFuzzer;
    private Timer shortNamePollTimer;

    @Override
    public String getTabCaption() {
        return "IIS Tilde Enumeration";
    }

    @Override
    public Component getUiComponent() {
        return mainUI;
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println(NAME + " v" + VERSION + "\nBy " + AUTHOR);

        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(new ScannerCheck(callbacks));

        SwingUtilities.invokeLater(this::buildUi);
    }

    // -------------------------------------------------------------------------
    // UI construction
    // -------------------------------------------------------------------------

    private void buildUi() {
        mainUI = new JTabbedPane();
        mainUI.setBorder(new EmptyBorder(6, 6, 6, 6));

        // Field widgets shared across tabs
        targetUrlField = new JTextField("", 50);
        nThreadsField = new JTextField("20", 4);
        requestEditor = new JTextPane();
        requestEditor.setFont(new Font("Monospaced", Font.PLAIN, 13));
        requestEditor.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));
        requestEditor.setText(
                "§METHOD§ §PATH§ HTTP/1.1\n" +
                "Host: §HOST§\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36\n" +
                "\n");

        statusLabel = new JLabel("Ready to scan");
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setString("");
        progressBar.setValue(0);

        logPane = new ColoredLogPane();
        logPane.setText("IIS Tilde Enumeration Scanner Burp Extension is ready\nThe scan output will be displayed here");

        exploitModeCheckbox = new JCheckBox("Exploit the vulnerability (opt out for vulnerability check only)", true);
        completeFileGuessSitemapCheckbox = new JCheckBox(
                "Use Burp sitemap words to create an Intruder payload set with possible filenames", false);
        completeFileGuessWordlistCheckbox = new JCheckBox(
                "Use wordlist to create an Intruder payload set with possible filenames", false);
        tildeGuessCheckbox = new JCheckBox(
                "Enable tildeGuess reverse-search algorithm (Phase 2) for dictionary export + fuzz", false);

        fileNamePicker = new WordlistPicker(WordlistLoader.BUNDLED_FILENAME_LISTS, "bundled:big");
        fileExtPicker = new WordlistPicker(WordlistLoader.BUNDLED_EXTENSION_LISTS, "bundled:extensions");

        mainUI.addTab("Scanner", buildScannerTab());
        mainUI.addTab("Fuzz Hits", buildFuzzHitsTab());
        fuzzHitsTabIndex = mainUI.indexOfTab("Fuzz Hits");
        mainUI.addTab("Configuration", buildConfigurationTab());

        callbacks.customizeUiComponent(mainUI);
        callbacks.addSuiteTab(BurpExtender.this);

        startShortNamePollTimer();
    }

    // -------------------------------------------------------------------------
    // Scanner tab — toolbar + split (log | discovered short names) + status bar
    // -------------------------------------------------------------------------

    private JPanel buildScannerTab() {
        JPanel root = new JPanel(new BorderLayout(0, 6));
        root.setBorder(new EmptyBorder(6, 6, 6, 6));

        root.add(buildScannerToolbar(), BorderLayout.NORTH);

        JScrollPane logScroll = new JScrollPane(logPane);
        logScroll.setBorder(BorderFactory.createTitledBorder("Live Log"));

        shortNameTable = new JTable(shortNameModel);
        shortNameTable.setRowSorter(new TableRowSorter<>(shortNameModel));
        shortNameTable.setFillsViewportHeight(true);
        shortNameTable.setShowGrid(false);
        TableColumn typeCol = shortNameTable.getColumnModel().getColumn(ShortNameTableModel.COL_TYPE);
        typeCol.setMaxWidth(60);
        typeCol.setPreferredWidth(50);
        shortNameTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeShortNamePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShortNamePopup(e); }
        });

        JScrollPane tableScroll = new JScrollPane(shortNameTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Discovered Short Names"));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, logScroll, tableScroll);
        split.setResizeWeight(0.55);
        split.setDividerSize(6);
        root.add(split, BorderLayout.CENTER);

        root.add(buildStatusBar(), BorderLayout.SOUTH);
        return root;
    }

    private JToolBar buildScannerToolbar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        bar.setRollover(true);
        bar.setBorder(new EmptyBorder(4, 4, 4, 4));

        bar.add(new JLabel("Target URL: "));
        bar.add(targetUrlField);
        bar.addSeparator();
        bar.add(new JLabel("Threads: "));
        bar.add(nThreadsField);
        bar.addSeparator();

        scanButton = new JButton("▶ Scan");
        scanButton.setBackground(ACCENT);
        scanButton.setForeground(Color.WHITE);
        scanButton.setFont(new Font("Nimbus", Font.BOLD, 13));
        scanButton.addActionListener(buildScanListener());
        bar.add(scanButton);

        bar.addSeparator();

        JButton saveBtn = new JButton("Save Output");
        saveBtn.addActionListener(e -> Utils.saveOutputToFile(callbacks, logPane, targetUrlField));
        bar.add(saveBtn);

        JButton exportBtn = new JButton("Export Dictionary");
        exportBtn.addActionListener(e -> doExportDictionary());
        bar.add(exportBtn);

        fuzzButton = new JButton("↻ Fuzz Real Paths");
        fuzzButton.setBackground(SCAN_GREEN);
        fuzzButton.setForeground(Color.WHITE);
        fuzzButton.setFont(new Font("Nimbus", Font.BOLD, 13));
        fuzzButton.addActionListener(buildFuzzListener());
        bar.add(fuzzButton);

        bar.add(Box.createHorizontalGlue());
        return bar;
    }

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout(8, 0));
        bar.setBorder(new EmptyBorder(2, 4, 2, 4));
        bar.add(statusLabel, BorderLayout.WEST);
        progressBar.setPreferredSize(new java.awt.Dimension(220, 18));
        bar.add(progressBar, BorderLayout.EAST);
        return bar;
    }

    // -------------------------------------------------------------------------
    // Fuzz Hits tab
    // -------------------------------------------------------------------------

    private JPanel buildFuzzHitsTab() {
        JPanel root = new JPanel(new BorderLayout(0, 6));
        root.setBorder(new EmptyBorder(6, 6, 6, 6));

        fuzzHitTable = new JTable(fuzzHitModel);
        fuzzSorter = new TableRowSorter<>(fuzzHitModel);
        fuzzHitTable.setRowSorter(fuzzSorter);
        fuzzHitTable.setFillsViewportHeight(true);
        fuzzHitTable.setShowGrid(false);
        TableColumn statusCol = fuzzHitTable.getColumnModel().getColumn(FuzzHitTableModel.COL_STATUS);
        statusCol.setMaxWidth(70);
        statusCol.setPreferredWidth(60);
        statusCol.setCellRenderer(new StatusCodeCellRenderer());
        TableColumn timeCol = fuzzHitTable.getColumnModel().getColumn(FuzzHitTableModel.COL_TIME);
        timeCol.setMaxWidth(80);
        timeCol.setPreferredWidth(80);
        TableColumn lenCol = fuzzHitTable.getColumnModel().getColumn(FuzzHitTableModel.COL_LENGTH);
        lenCol.setMaxWidth(90);
        lenCol.setPreferredWidth(80);

        fuzzHitTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeFuzzPopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeFuzzPopup(e); }
        });

        JToolBar tb = new JToolBar();
        tb.setFloatable(false);
        tb.setBorder(new EmptyBorder(2, 2, 2, 2));
        tb.add(new JLabel("Filter: "));
        fuzzFilterField = new JTextField(24);
        fuzzFilterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFuzzFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFuzzFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFuzzFilter(); }
        });
        tb.add(fuzzFilterField);
        tb.addSeparator();

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            fuzzHitModel.clear();
            refreshFuzzTabTitle();
        });
        tb.add(clearBtn);

        JButton exportBtn = new JButton("Export Hits to TXT");
        exportBtn.addActionListener(e -> doExportFuzzHits());
        tb.add(exportBtn);
        tb.add(Box.createHorizontalGlue());

        root.add(tb, BorderLayout.NORTH);
        root.add(new JScrollPane(fuzzHitTable), BorderLayout.CENTER);
        return root;
    }

    private void applyFuzzFilter() {
        String txt = fuzzFilterField.getText().trim();
        if (txt.isEmpty()) fuzzSorter.setRowFilter(null);
        else fuzzSorter.setRowFilter(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(txt)));
    }

    // -------------------------------------------------------------------------
    // Configuration tab — sectioned with TitledBorder + GridBagLayout
    // -------------------------------------------------------------------------

    private JSplitPane buildConfigurationTab() {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setBorder(new EmptyBorder(10, 10, 10, 10));
        split.setResizeWeight(0.45);

        // Left: HTTP request editor
        JPanel left = new JPanel(new BorderLayout(0, 6));
        left.setBorder(BorderFactory.createTitledBorder("Request Template"));
        JScrollPane requestScroll = new JScrollPane(requestEditor);
        left.add(requestScroll, BorderLayout.CENTER);

        // Right: stacked sections in a scroll pane
        JPanel sections = new JPanel();
        sections.setLayout(new BoxLayout(sections, BoxLayout.Y_AXIS));
        sections.add(buildHttpSection());
        sections.add(buildTildeMagicSection());
        sections.add(buildFilenameConstraintsSection());
        sections.add(buildPerformanceSection());
        sections.add(buildFuzzSection());
        sections.add(buildFilenameGuessingSection());

        JScrollPane right = new JScrollPane(sections);
        right.getVerticalScrollBar().setUnitIncrement(16);
        right.setBorder(BorderFactory.createEmptyBorder());

        split.setLeftComponent(left);
        split.setRightComponent(right);

        // Defer divider position until laid out
        Timer t = new Timer(300, e -> split.setDividerLocation(0.45));
        t.setRepeats(false);
        t.start();

        return split;
    }

    private JPanel buildHttpSection() {
        JPanel p = UiBuilders.titledSection("HTTP Request");
        int row = 0;
        UiBuilders.addLabeledRow(p, row++, "Request methods (comma-separated):", textField("requestMethods",
                "OPTIONS,POST,DEBUG,TRACE,GET,HEAD", 30));
        UiBuilders.addLabeledRow(p, row++, "URL suffix for error display:", textField("urlSuffix",
                "?&aspxerrorpath=/", 30));
        UiBuilders.addLabeledRow(p, row++, "Delay between requests (ms):", textField("delay", "0", 8));
        return p;
    }

    private JPanel buildTildeMagicSection() {
        JPanel p = UiBuilders.titledSection("Tilde Enumeration Magic Values");
        int row = 0;
        UiBuilders.addLabeledRow(p, row++, "Magic final part list (comma-separated):", textField("magicFinalPartList",
                "/~1/.rem,/~1/,\\a.aspx,\\a.asp,/a.aspx,/a.asp,/a.shtml,/a.asmx,/a.ashx,/a.config,/a.php,/a.jpg,/webresource.axd,/a.xxx",
                40));
        UiBuilders.addLabeledRow(p, row++, "Question mark symbol:", textField("questionMarkSymbol", "?", 4));
        UiBuilders.addLabeledRow(p, row++, "Asterisk symbol:", textField("asteriskSymbol", "*", 4));
        UiBuilders.addLabeledRow(p, row++, "Magic file name:", textField("magicFileName", "*~1*", 8));
        UiBuilders.addLabeledRow(p, row++, "Magic file extension:", textField("magicFileExt", "*", 4));
        return p;
    }

    private JPanel buildFilenameConstraintsSection() {
        JPanel p = UiBuilders.titledSection("Filename Constraints");
        int row = 0;
        UiBuilders.addLabeledRow(p, row++, "File name starts with:", textField("nameStartsWith", "", 12));
        UiBuilders.addLabeledRow(p, row++, "File extension starts with:", textField("extStartsWith", "", 12));
        UiBuilders.addLabeledRow(p, row++, "Max numerical part (~N):", textField("maxNumericalPart", "4", 4));
        UiBuilders.addLabeledRow(p, row++, "Force numerical part:", textField("forceNumericalPart", "1", 4));
        UiBuilders.addLabeledRow(p, row++, "In-scope characters:", textField("inScopeCharacters",
                "ETAONRISHDLFCMUGYPWBVKJXQZ0123456789_-$~()&!#%'@^`{}", 40));
        return p;
    }

    private JPanel buildPerformanceSection() {
        JPanel p = UiBuilders.titledSection("Performance & Detection");
        int row = 0;
        UiBuilders.addLabeledRow(p, row++, "Dynamic content strip level (higher = more aggressive):",
                textField("stripLevel", "1", 4));
        UiBuilders.addLabeledRow(p, row++, "Delta for response difference (bytes):",
                textField("deltaResponseLength", "75", 4));
        return p;
    }

    private JPanel buildFuzzSection() {
        JPanel p = UiBuilders.titledSection("Fuzz Real Paths");
        int row = 0;
        UiBuilders.addLabeledRow(p, row++, "Success status codes (comma-separated):",
                textField("successCodes", "200,204,301,302,307,401,403", 30));
        return p;
    }

    private JPanel buildFilenameGuessingSection() {
        JPanel p = UiBuilders.titledSection("Filename Guessing & Wordlists");
        int row = 0;
        UiBuilders.addFullRow(p, row++, completeFileGuessSitemapCheckbox);
        UiBuilders.addFullRow(p, row++, completeFileGuessWordlistCheckbox);
        UiBuilders.addFullRow(p, row++, tildeGuessCheckbox);
        UiBuilders.addLabeledRow(p, row++, "Filename wordlist:", fileNamePicker);
        UiBuilders.addLabeledRow(p, row++, "Extension wordlist:", fileExtPicker);
        return p;
    }

    private JTextField textField(String key, String defaultValue, int columns) {
        JTextField tf = new JTextField(defaultValue, columns);
        confFields.put(key, tf);
        return tf;
    }

    // -------------------------------------------------------------------------
    // Scan / fuzz action listeners
    // -------------------------------------------------------------------------

    private ActionListener buildScanListener() {
        return new ActionListener() {
            @Override public void actionPerformed(ActionEvent a) {
                if (tildeEnumerationScanner != null && tildeEnumerationScanner.isAlive()) {
                    tildeEnumerationScanner.interrupt();
                    return;
                }
                if (!checkValidFieldValues()) return;

                shortNameModel.clear();
                progressBar.setIndeterminate(true);
                progressBar.setString("scanning…");
                statusLabel.setText("Scanning " + targetUrlField.getText());

                tildeEnumerationScanner = new TildeEnumerationScanner(
                        targetUrlField.getText(),
                        new Config(confFields, requestEditor, nThreadsField,
                                exploitModeCheckbox, completeFileGuessSitemapCheckbox,
                                completeFileGuessWordlistCheckbox, tildeGuessCheckbox,
                                fileNamePicker, fileExtPicker),
                        new Output(logPane, statusLabel, callbacks),
                        scanButton, callbacks);

                // Watcher thread resets progress bar when scan completes
                Thread watcher = new Thread(() -> {
                    try {
                        tildeEnumerationScanner.join();
                    } catch (InterruptedException ignored) {}
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setIndeterminate(false);
                        progressBar.setString("");
                        progressBar.setValue(0);
                    });
                });
                watcher.setDaemon(true);
                watcher.start();

                tildeEnumerationScanner.start();
            }
        };
    }

    private ActionListener buildFuzzListener() {
        return new ActionListener() {
            @Override public void actionPerformed(ActionEvent a) {
                if (pathFuzzer != null && pathFuzzer.isAlive()) {
                    pathFuzzer.interrupt();
                    fuzzButton.setText("↻ Fuzz Real Paths");
                    return;
                }
                if (tildeEnumerationScanner == null) {
                    logPane.setText(logPane.getText() + "\n[X] Nothing to fuzz — run a scan first");
                    return;
                }
                List<DictionaryGenerator.ShortName> shortNames =
                        DictionaryGenerator.fromBruteforcerResults(
                                tildeEnumerationScanner.getFilesFound(),
                                tildeEnumerationScanner.getDirsFound());
                if (shortNames.isEmpty()) {
                    logPane.setText(logPane.getText() + "\n[X] No short names to fuzz — run a scan first");
                    return;
                }

                List<String> dict = WordlistLoader.load(fileNamePicker.getSelected());
                List<String> exts = WordlistLoader.load(fileExtPicker.getSelected());
                List<String> candidates = DictionaryGenerator.generate(
                        shortNames, dict, exts, tildeGuessCheckbox.isSelected());
                if (candidates.isEmpty()) {
                    logPane.setText(logPane.getText() + "\n[X] No candidates produced — check wordlist source");
                    return;
                }

                String targetUrl = targetUrlField.getText().trim();
                if (targetUrl.isEmpty() || !targetUrl.contains("://")) {
                    logPane.setText(logPane.getText() + "\n[X] Target URL is empty or malformed");
                    return;
                }

                int delay;
                int nThreads;
                try {
                    delay = Integer.parseInt(confFields.get("delay").getText());
                    nThreads = Integer.parseInt(nThreadsField.getText());
                } catch (NumberFormatException nfe) {
                    logPane.setText(logPane.getText() + "\n[X] Invalid delay / thread count");
                    return;
                }

                final Requester req;
                try {
                    req = new Requester(targetUrl + confFields.get("urlSuffix").getText(), delay, callbacks);
                } catch (RuntimeException re) {
                    logPane.setText(logPane.getText() + "\n[X] Failed to build requester: " + re.getMessage());
                    return;
                }

                final String reqTemplate = requestEditor.getText()
                        .replace("§METHOD§", "GET")
                        .replace("\n", "\r\n");

                PathFuzzer.RequestSender sender = relativePath -> {
                    try {
                        String fullPath = req.getBasePath() + Utils.urlEncode(relativePath);
                        IHttpRequestResponse rr = req.httpRequestRaw(reqTemplate.replace("§PATH§", fullPath));
                        if (rr == null || rr.getResponse() == null) return PathFuzzer.ResponseInfo.ERROR;
                        IResponseInfo info = callbacks.getHelpers().analyzeResponse(rr.getResponse());
                        int status = info.getStatusCode();
                        int length = rr.getResponse().length - info.getBodyOffset();
                        return new PathFuzzer.ResponseInfo(status, length);
                    } catch (RuntimeException e) {
                        return PathFuzzer.ResponseInfo.ERROR;
                    }
                };

                Set<Integer> successCodes = PathFuzzer.parseCodes(confFields.get("successCodes").getText());

                logPane.setText(logPane.getText() + String.format(
                        "\n[*] Fuzzing %d candidates against %s (threads=%d, success codes=%s)",
                        candidates.size(), targetUrl, nThreads, successCodes));

                fuzzButton.setText("■ Stop Fuzz");
                progressBar.setIndeterminate(false);
                progressBar.setMinimum(0);
                progressBar.setMaximum(candidates.size());
                progressBar.setValue(0);
                progressBar.setString("0/" + candidates.size());

                IHttpService svc = req.getHttpService();
                String absoluteBase = (svc.getProtocol() == null ? "http" : svc.getProtocol())
                        + "://" + svc.getHost()
                        + (svc.getPort() == defaultPort(svc.getProtocol()) ? "" : ":" + svc.getPort());

                pathFuzzer = new PathFuzzer(candidates, sender, successCodes, nThreads,
                        new PathFuzzer.ProgressReporter() {
                            @Override
                            public void onAttempt(String candidate, int status, int length, boolean hit) {
                                SwingUtilities.invokeLater(() -> {
                                    progressBar.setValue(pathFuzzer.sentCount());
                                    progressBar.setString(pathFuzzer.sentCount() + "/" + pathFuzzer.candidateCount());
                                    if (hit) {
                                        String full = absoluteBase + req.getBasePath() + candidate;
                                        fuzzHitModel.append(new FuzzHitTableModel.Row(status, full, length, System.currentTimeMillis()));
                                        refreshFuzzTabTitle();
                                        logPane.setText(logPane.getText() + String.format(
                                                "\n[+] HIT %d  %s  (%d bytes)", status, full, length));
                                    }
                                });
                            }

                            @Override
                            public void onFinish(int sent, int hits) {
                                SwingUtilities.invokeLater(() -> {
                                    fuzzButton.setText("↻ Fuzz Real Paths");
                                    statusLabel.setText("Fuzz complete: " + hits + " hits / " + sent + " sent");
                                    progressBar.setString("done");
                                    logPane.setText(logPane.getText() + String.format(
                                            "\n[+] Fuzz finished: %d requests, %d hits", sent, hits));
                                });
                            }
                        });
                pathFuzzer.start();
            }
        };
    }

    private static int defaultPort(String protocol) {
        return "https".equalsIgnoreCase(protocol) ? 443 : 80;
    }

    private void refreshFuzzTabTitle() {
        if (fuzzHitsTabIndex >= 0) {
            int n = fuzzHitModel.getRowCount();
            mainUI.setTitleAt(fuzzHitsTabIndex, n == 0 ? "Fuzz Hits" : "Fuzz Hits (" + n + ")");
        }
    }

    // -------------------------------------------------------------------------
    // Export / context menus
    // -------------------------------------------------------------------------

    private void doExportDictionary() {
        if (tildeEnumerationScanner == null) {
            logPane.setText(logPane.getText() + "\n[X] Nothing to export — run a scan first");
            return;
        }
        int n = Utils.exportDictionary(callbacks, targetUrlField,
                tildeEnumerationScanner.getFilesFound(),
                tildeEnumerationScanner.getDirsFound(),
                fileNamePicker.getSelected(),
                fileExtPicker.getSelected(),
                tildeGuessCheckbox.isSelected());
        if (n < 0) {
            logPane.setText(logPane.getText() + "\n[X] No dictionary candidates produced (or export cancelled)");
        } else {
            logPane.setText(logPane.getText() + "\n[+] Dictionary exported: " + n + " unique candidates");
        }
    }

    private void doExportFuzzHits() {
        if (fuzzHitModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(mainUI, "No fuzz hits to export.");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (FuzzHitTableModel.Row r : fuzzHitModel.snapshot()) {
            sb.append(r.status).append('\t').append(r.url).append('\n');
        }
        javax.swing.JFileChooser fc = new javax.swing.JFileChooser();
        fc.setSelectedFile(new java.io.File("iis-tilde-fuzz-hits.txt"));
        if (fc.showSaveDialog(mainUI) != javax.swing.JFileChooser.APPROVE_OPTION) return;
        try {
            java.nio.file.Files.writeString(fc.getSelectedFile().toPath(), sb.toString());
        } catch (java.io.IOException e) {
            JOptionPane.showMessageDialog(mainUI, "Export failed: " + e.getMessage());
        }
    }

    private void maybeShortNamePopup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int viewRow = shortNameTable.rowAtPoint(e.getPoint());
        if (viewRow < 0) return;
        if (!shortNameTable.isRowSelected(viewRow)) shortNameTable.setRowSelectionInterval(viewRow, viewRow);
        int modelRow = shortNameTable.convertRowIndexToModel(viewRow);
        ShortNameTableModel.Row row = shortNameModel.rowAt(modelRow);
        if (row == null) return;

        JPopupMenu menu = new JPopupMenu();
        JMenuItem copy = new JMenuItem("Copy short name");
        copy.addActionListener(ev -> Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(row.name), null));
        menu.add(copy);
        menu.show(e.getComponent(), e.getX(), e.getY());
    }

    private void maybeFuzzPopup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int viewRow = fuzzHitTable.rowAtPoint(e.getPoint());
        if (viewRow < 0) return;
        if (!fuzzHitTable.isRowSelected(viewRow)) fuzzHitTable.setRowSelectionInterval(viewRow, viewRow);
        int modelRow = fuzzHitTable.convertRowIndexToModel(viewRow);
        FuzzHitTableModel.Row row = fuzzHitModel.rowAt(modelRow);
        if (row == null) return;

        JPopupMenu menu = new JPopupMenu();
        menu.add(menuItem("Send to Repeater", () -> sendHitToRepeater(row)));
        menu.add(menuItem("Open in Browser", () -> openInBrowser(row.url)));
        menu.add(menuItem("Copy URL", () -> Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(row.url), null)));
        menu.show(e.getComponent(), e.getX(), e.getY());
    }

    private JMenuItem menuItem(String label, Runnable action) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(e -> action.run());
        return item;
    }

    private void sendHitToRepeater(FuzzHitTableModel.Row row) {
        try {
            URL u = new URL(row.url);
            int port = u.getPort() == -1 ? defaultPort(u.getProtocol()) : u.getPort();
            boolean https = "https".equalsIgnoreCase(u.getProtocol());
            String path = u.getPath() + (u.getQuery() != null ? "?" + u.getQuery() : "");
            String reqText = "GET " + path + " HTTP/1.1\r\n"
                    + "Host: " + u.getHost() + "\r\n"
                    + "User-Agent: IIS-Tilde-Enum\r\n\r\n";
            callbacks.sendToRepeater(u.getHost(), port, https, reqText.getBytes(), "IIS Tilde Hit " + row.status);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(mainUI, "Send to Repeater failed: " + ex.getMessage());
        }
    }

    private void openInBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
            }
        } catch (Exception ignored) {}
    }

    // -------------------------------------------------------------------------
    // Live polling: drains bruteforcer results into the short-name table
    // -------------------------------------------------------------------------

    private void startShortNamePollTimer() {
        shortNamePollTimer = new Timer(500, e -> {
            if (tildeEnumerationScanner == null) return;
            for (String f : tildeEnumerationScanner.getFilesFound()) {
                if (f != null) shortNameModel.append(new ShortNameTableModel.Row("File", f));
            }
            for (String d : tildeEnumerationScanner.getDirsFound()) {
                if (d != null) shortNameModel.append(new ShortNameTableModel.Row("Dir", d));
            }
        });
        shortNamePollTimer.start();
    }

    // -------------------------------------------------------------------------
    // Field validation (kept compatible with the previous behavior)
    // -------------------------------------------------------------------------

    private boolean checkValidFieldValues() {
        String[] intFields = {
                "deltaResponseLength", "stripLevel", "delay",
                "maxNumericalPart", "forceNumericalPart"
        };
        try { Integer.parseInt(nThreadsField.getText()); }
        catch (NumberFormatException e) { error("number of threads must be an integer"); return false; }
        for (String key : intFields) {
            try { Integer.parseInt(confFields.get(key).getText()); }
            catch (NumberFormatException e) { error(key + " must be an integer"); return false; }
        }
        return true;
    }

    private void error(String msg) {
        logPane.setText("[X] Error: " + msg);
    }
}
