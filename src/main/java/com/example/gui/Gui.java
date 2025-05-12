package com.example.gui;

import javax.swing.*;
import java.awt.*;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import com.example.util.LivePacketReader;
import com.example.util.PacketParser;
import com.example.util.Rule;
import com.example.detection.RuleEngine;
import com.example.IDPSController;
import com.example.detection.Alert;
import com.example.detection.AlertType;
import com.example.detection.Severity;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Gui extends JFrame {
    private JComboBox<String> interfaceComboBox;
    private JComboBox<String> protocolComboBox;
    private JButton buttonStart;
    private JButton buttonStop;
    private JButton buttonExit;
    private JTextArea packetArea;
    private JTextArea statsArea;
    private JTextPane logArea;
    private JTextPane rlDecisionsArea;
    private JLabel statusLabel;
    private JCheckBox rlEnabledCheckbox;
    private LivePacketReader packetReader;
    private RuleEngine ruleEngine;
    private IDPSController idpsController;
    private boolean isCapturing = false;
    private Thread captureThread;
    private String selectedProtocol = "ALL";

    
    // Statistiques
    private AtomicInteger tcpCount = new AtomicInteger(0);
    private AtomicInteger udpCount = new AtomicInteger(0);
    private AtomicInteger httpCount = new AtomicInteger(0);
    private AtomicInteger httpsCount = new AtomicInteger(0);
    private AtomicInteger suspiciousCount = new AtomicInteger(0);
    private AtomicInteger alertCount = new AtomicInteger(0);
    
    // Log file
    private static final String LOG_DIR = "logs";
    private FileWriter logWriter;
    private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private Map<String, String> lastDisplayedPacket;

    private JButton simulateDdosButton;
    private JButton simulateSqlInjectionButton;
    private JButton simulatePortScanButton;
    private ScheduledExecutorService simulationExecutor;
    private JButton testSnortRulesButton;
    private Random random = new Random();

    private static final Logger LOGGER = Logger.getLogger(Gui.class.getName());

    private JButton showActiveRulesButton;

    private Alert lastAlert; // Variable pour stocker la dernière alerte

    public Gui() {
        idpsController = new IDPSController();
        initializeComponents();
        setupLayout();
        setupListeners();
        loadNetworkInterfaces();
        createLogDirectory();
        initializeRules();
        initializeRL();
        initializeSnortRules();

        // --- Ajout d'une règle de test qui matchera toujours les paquets simulés ---
        Rule testRule = new Rule();
        testRule.setProtocol("TCP");
        testRule.setSourceIp("any");
        testRule.setSourcePort("any");
        testRule.setDestinationIp("any");
        testRule.setDestinationPort("any");
        testRule.addOption("content", "UNION SELECT");
        testRule.addOption("msg", "Test alert: SQLi detected");
        testRule.addOption("severity", "HIGH");
        if (ruleEngine != null)
            ruleEngine.addRule(testRule);
    }

    public void setRules(List<Rule> rules) {
        if (ruleEngine == null) {
            ruleEngine = new RuleEngine();
        }
        ruleEngine.setRules(rules);
        updateStatsDisplay();
    }

    private void initializeRules() {
        ruleEngine = new RuleEngine();
        // Les règles seront définies via setRules()
    }

    private void initializeComponents() {
        setTitle("Network Intrusion Detection System");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1600, 900);

        interfaceComboBox = new JComboBox<>();
        protocolComboBox = new JComboBox<>(new String[] { "ALL", "TCP", "UDP", "HTTP", "HTTPS" });
        buttonStart = new JButton("Start Capture");
        buttonStop = new JButton("Stop Capture");
        buttonExit = new JButton("Exit");
        rlEnabledCheckbox = new JCheckBox("Enable RL IP Control");
        rlEnabledCheckbox.setSelected(false);
        
        packetArea = new JTextArea();
        statsArea = new JTextArea();
        logArea = new JTextPane();
        rlDecisionsArea = new javax.swing.JTextPane();
        statusLabel = new JLabel("Status: Ready");

        buttonStop.setEnabled(false);
        packetArea.setEditable(false);
        statsArea.setEditable(false);
        logArea.setEditable(false);
        rlDecisionsArea.setEditable(false);
        
        // Configuration des zones de texte
        packetArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        statsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        rlDecisionsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        
        // Couleurs de fond
        packetArea.setBackground(new Color(240, 240, 240));
        statsArea.setBackground(new Color(245, 245, 245));
        logArea.setBackground(new Color(250, 250, 250));
        rlDecisionsArea.setBackground(new Color(250, 250, 250));

        // Initialize simulation buttons
        simulateDdosButton = new JButton("Simulate XSS Attack");
        simulateSqlInjectionButton = new JButton("Simulate SQL Injection");
        simulatePortScanButton = new JButton("Simulate Port Scan");
        testSnortRulesButton = new JButton("Test Snort Rules");

        // Add action listeners
        simulateDdosButton.addActionListener(e -> simulateXssAttack());
        simulateSqlInjectionButton.addActionListener(e -> simulateSqlInjection());
        simulatePortScanButton.addActionListener(e -> simulatePortScan());
        testSnortRulesButton.addActionListener(e -> testSnortRules());

        // Disable buttons initially
        simulateDdosButton.setEnabled(false);
        simulateSqlInjectionButton.setEnabled(false);
        simulatePortScanButton.setEnabled(false);
        testSnortRulesButton.setEnabled(false);

        // Initialiser le bouton pour afficher les règles actives
        showActiveRulesButton = new JButton("Afficher les règles actives");
        showActiveRulesButton.addActionListener(e -> showActiveRules());
    }

    private void setupLayout() {
        // Panel supérieur
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Main controls row
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlsPanel.add(new JLabel("Network Interface:"));
        controlsPanel.add(interfaceComboBox);
        controlsPanel.add(new JLabel("Protocol:"));
        controlsPanel.add(protocolComboBox);
        controlsPanel.add(buttonStart);
        controlsPanel.add(buttonStop);
        controlsPanel.add(buttonExit);
        controlsPanel.add(rlEnabledCheckbox);
        
        controlsPanel.add(statusLabel);

        // Simulation panel row
        JPanel simulationPanel = new JPanel(new GridLayout(2, 2, 5, 5));
        simulationPanel.setBorder(BorderFactory.createTitledBorder("Attack Simulations"));
        simulationPanel.add(simulateDdosButton);
        simulationPanel.add(simulateSqlInjectionButton);
        simulationPanel.add(simulatePortScanButton);
        simulationPanel.add(testSnortRulesButton);

        // Add both rows to the top panel
        topPanel.add(controlsPanel);
        topPanel.add(simulationPanel);

        // Panel principal avec JSplitPane
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplitPane.setDividerLocation(800);
        
        // Panel gauche (paquets)
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("Captured Packets"));
        JScrollPane packetScroll = new JScrollPane(packetArea);
        packetScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        leftPanel.add(packetScroll, BorderLayout.CENTER);
        
        // Panel droit
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplitPane.setDividerLocation(300);

        // Panel supérieur (stats + RL)
        JPanel upperRightPanel = new JPanel(new GridLayout(2, 1));
        
        // Panel statistiques
        JPanel statsPanel = new JPanel(new BorderLayout());
        statsPanel.setBorder(BorderFactory.createTitledBorder("Statistics"));
        JScrollPane statsScroll = new JScrollPane(statsArea);
        statsPanel.add(statsScroll, BorderLayout.CENTER);

        // Panel RL
        JPanel rlPanel = new JPanel(new BorderLayout());
        rlPanel.setBorder(BorderFactory.createTitledBorder("RL Prevention Decisions"));
        JScrollPane rlScroll = new JScrollPane(rlDecisionsArea);
        rlPanel.add(rlScroll, BorderLayout.CENTER);

        upperRightPanel.add(statsPanel);
        upperRightPanel.add(rlPanel);
        
        // Panel logs
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Logs & Alerts"));
        JScrollPane logScroll = new JScrollPane(logArea);
        logPanel.add(logScroll, BorderLayout.CENTER);
        
        rightSplitPane.setTopComponent(upperRightPanel);
        rightSplitPane.setBottomComponent(logPanel);
        
        mainSplitPane.setLeftComponent(leftPanel);
        mainSplitPane.setRightComponent(rightSplitPane);
        
        setLayout(new BorderLayout());
        add(topPanel, BorderLayout.NORTH);
        add(mainSplitPane, BorderLayout.CENTER);

        // Ajouter le bouton à la disposition
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(showActiveRulesButton);
        // Ajoutez le panneau de boutons à votre disposition principale
        add(buttonPanel, BorderLayout.SOUTH); // Ajustez la position selon vos besoins
    }

    private void createLogDirectory() {
        File dir = new File(LOG_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        try {
            String logFile = LOG_DIR + "/ids_" + new SimpleDateFormat("yyyy-MM-dd").format(new Date()) + ".log";
            logWriter = new FileWriter(logFile, true);
        } catch (IOException e) {
            insertText(logArea, "Error creating log file: " + e.getMessage() + "\n");
        }
    }

    private void initializeRL() {
        // Configurer les callbacks pour le RL
        idpsController.setDecisionCallback(decision -> {
            SwingUtilities.invokeLater(() -> {
                appendColoredText(rlDecisionsArea, decision + "\n");
            });
        });

        idpsController.setStatsCallback(stats -> {
            SwingUtilities.invokeLater(() -> {
                updateRLStats(stats);
            });
        });

        // Charger et entraîner le modèle avec le fichier CSV
        try {
            insertText(rlDecisionsArea, "Loading RL model from test_csv.csv...\n");
            idpsController.train("test_csv.csv");
            insertText(rlDecisionsArea, "RL model trained successfully\n");
        } catch (Exception e) {
            insertText(rlDecisionsArea, "Error training RL model: " + e.getMessage() + "\n");
            e.printStackTrace();
            // Créer un fichier CSV vide si nécessaire
            try {
                File csvFile = new File("test_csv.csv");
                if (!csvFile.exists()) {
                    try (FileWriter fw = new FileWriter(csvFile)) {
                        fw.write("protocol,srcPort,srcIP,destPort,destIP,isMalicious,action\n");
                    }
                    insertText(rlDecisionsArea, "Created empty training file: test_csv.csv\n");
                }
            } catch (IOException ex) {
                insertText(rlDecisionsArea, "Error creating CSV file: " + ex.getMessage() + "\n");
            }
        }
    }

    private void insertText(JTextPane pane, String text) {
        try {
            pane.getDocument().insertString(pane.getDocument().getLength(), text, null);
            pane.setCaretPosition(pane.getDocument().getLength());
        } catch (javax.swing.text.BadLocationException e) {
            e.printStackTrace();
        }
    }

    private void appendColoredText(JTextPane textPane, String text) {
        // Définir les styles de couleur
        javax.swing.text.Style style = textPane.addStyle("Color Style", null);

        try {
            if (text.contains("ALLOWED")) {
                javax.swing.text.StyleConstants.setForeground(style, new Color(0, 150, 0)); // Vert
            } else if (text.contains("BLOCKED")) {
                javax.swing.text.StyleConstants.setForeground(style, new Color(200, 0, 0)); // Rouge
            }

            // Ajouter le texte avec le style
            ((javax.swing.text.StyledDocument) textPane.getDocument()).insertString(
                    textPane.getDocument().getLength(), text, style);

            // Garder le focus sur les dernières lignes
            textPane.setCaretPosition(textPane.getDocument().getLength());
        } catch (javax.swing.text.BadLocationException e) {
            e.printStackTrace();
        }
    }

    private void appendColoredAlert(JTextPane textPane, String text, String severity) {
        // Définir la couleur en fonction de la sévérité
        Color color;
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                color = new Color(200, 0, 0); // Rouge foncé
                break;
            case "HIGH":
                color = new Color(255, 60, 60); // Rouge clair
                break;
            case "MEDIUM":
                color = new Color(255, 140, 0); // Orange
                break;
            case "LOW":
                color = new Color(255, 200, 0); // Jaune
                break;
            default:
                color = new Color(0, 0, 0); // Noir
        }

        // Créer un style avec la couleur
        javax.swing.text.Style style = ((javax.swing.text.StyledDocument) textPane.getDocument())
                .addStyle("Alert Style", null);
        javax.swing.text.StyleConstants.setForeground(style, color);

        try {
            ((javax.swing.text.StyledDocument) textPane.getDocument()).insertString(
                    textPane.getDocument().getLength(), text, style);
            textPane.setCaretPosition(textPane.getDocument().getLength());
        } catch (javax.swing.text.BadLocationException e) {
            LOGGER.log(Level.SEVERE, "Error appending colored alert", e);
        }
    }

    private void updateRLStats(Map<String, Object> stats) {
        if (statsArea.getText().isEmpty()) {
            // Premier affichage des stats
            StringBuilder sb = new StringBuilder();
            sb.append("=== RL Statistics ===\n");
            sb.append("Allowed packets: 0\n");
            sb.append("Blocked packets: 0\n");
            sb.append("Test Accuracy: 0.0% (0/0)\n");
            sb.append("==================\n\n");
            statsArea.setText(sb.toString());
        }

        // Get test accuracy from stats
        int correct = (int) stats.get("correctCount");
        int total = (int) stats.get("totalCount");
        double accuracy = total > 0 ? (100.0 * correct / total) : 0.0;

        // Mettre à jour uniquement les nombres
        String currentText = statsArea.getText();
        String updatedText = currentText.replaceFirst(
                "Allowed packets: \\d+",
                "Allowed packets: " + stats.get("allowedCount")).replaceFirst(
                        "Blocked packets: \\d+",
                        "Blocked packets: " + stats.get("blockedCount"))
                .replaceFirst(
                        "Test Accuracy: [0-9.]+% \\(\\d+/\\d+\\)",
                        String.format("Test Accuracy: %.2f%% (%d/%d)", accuracy, correct, total));

        statsArea.setText(updatedText);
    }

    private void updateStatistics(Map<String, String> packetData) {
        String protocol = packetData.get("protocol");
        if (protocol == null) return;

        // Increment traffic counters based on protocol
        switch (protocol.toUpperCase()) {
            case "TCP":
            tcpCount.incrementAndGet();
                break;
            case "UDP":
                udpCount.incrementAndGet();
                break;
            case "ICMP":
                // Increment ICMP counter if needed
                break;
            case "HTTP":
                httpCount.incrementAndGet();
                tcpCount.incrementAndGet();
                break;
            case "HTTPS":
                httpsCount.incrementAndGet();
                tcpCount.incrementAndGet();
                break;
        }

        // Check for rule matches and anomalies
        List<Rule> matchedRules = ruleEngine.getMatchingRules(packetData);
        if (!matchedRules.isEmpty()) {
            alertCount.incrementAndGet();
            for (Rule rule : matchedRules) {
                String severity = rule.getOption("severity");
                String message = rule.getOption("msg");
                Alert alert = new Alert(
                    AlertType.RULE_MATCH,
                    Severity.valueOf(severity),
                    message,
                    new HashMap<>(packetData)
                );
                displayAlert(alert);
            }
        }

        Alert anomalyAlert = idpsController.getAnomalyDetector().detectAnomaly(packetData);
        if (anomalyAlert != null) {
            alertCount.incrementAndGet();
            displayAlert(anomalyAlert);
        }

        // Update the statistics display
        SwingUtilities.invokeLater(this::updateStatsDisplay);
    }

    private void displayAlert(Alert alert) {
        if (alert == null) {
            LOGGER.warning("Received null alert in displayAlert");
            return;
        }

        lastAlert = alert;
        SwingUtilities.invokeLater(() -> {
            try {
            StringBuilder alertMessage = new StringBuilder();
            alertMessage.append(String.format("[%s] [%s] ALERT: %s\n",
                    dateFormat.format(new Date()),
                    alert.getSeverity(),
                    alert.getMessage()));

            Map<String, String> packetData = alert.getPacketData();
            if (packetData != null) {
                alertMessage.append(String.format("Source: %s:%s\n",
                        packetData.get("srcIP"),
                        packetData.get("srcPort")));
                alertMessage.append(String.format("Destination: %s:%s\n",
                        packetData.get("destIP"),
                        packetData.get("destPort")));
                alertMessage.append(String.format("Protocol: %s\n",
                        packetData.get("protocol")));
                    alertMessage.append(String.format("Data: %s\n",
                            packetData.get("data")));
            }

            alertMessage.append("-------------------\n");
            appendColoredAlert(logArea, alertMessage.toString(), alert.getSeverity().toString());
                logArea.repaint();
            } catch (Exception e) {
                LOGGER.severe("Error displaying alert: " + e.getMessage());
            }
        });
    }

    private void logAlert(Map<String, String> packetData, List<Rule> matchedRules) {
        for (Rule rule : matchedRules) {
            Alert alert = new Alert(
                AlertType.RULE_MATCH,
                Severity.valueOf(rule.getOption("severity")),
                rule.getOption("msg"),
                new HashMap<>(packetData)
            );
            displayAlert(alert);
        }
    }

    private void updateStatsDisplay() {
        SwingUtilities.invokeLater(() -> {
            StringBuilder stats = new StringBuilder();
            stats.append("Traffic Statistics:\n");
            stats.append("TCP Traffic: ").append(tcpCount.get()).append("\n");
            stats.append("UDP Traffic: ").append(udpCount.get()).append("\n");
            stats.append("HTTP Traffic: ").append(httpCount.get()).append("\n");
            stats.append("HTTPS Traffic: ").append(httpsCount.get()).append("\n");
            stats.append("Alerts: ").append(alertCount.get()).append("\n");
            stats.append("Loaded Rules: ").append(ruleEngine.getRules().size()).append("\n\n");

            // Ajout des statistiques RL
            Map<String, Object> rlStats = idpsController.getStatistics(); // Supposons que cette méthode existe
            stats.append("Allowed packets: ").append(rlStats.get("allowedCount")).append("\n");
            stats.append("Blocked packets: ").append(rlStats.get("blockedCount")).append("\n");
            stats.append("Accuracy: ").append(rlStats.get("accuracy")).append("\n");

            statsArea.setText(stats.toString());
        });
    }

    private void startCapture() {
        if (interfaceComboBox.getSelectedItem() == null) {
            JOptionPane.showMessageDialog(this, "Please select a network interface");
            return;
        }

        try {
            String selectedInterface = interfaceComboBox.getSelectedItem().toString().split(" ")[0];
            packetReader = new LivePacketReader(selectedInterface);
            isCapturing = true;
            
            // Reset statistics
            tcpCount.set(0);
            udpCount.set(0);
            httpCount.set(0);
            httpsCount.set(0);
            suspiciousCount.set(0);
            alertCount.set(0);
            updateStatsDisplay();

            // Clear display areas
            packetArea.setText("");
            rlDecisionsArea.setText("");
            
            // Start capture thread
            captureThread = new Thread(() -> {
                while (isCapturing) {
                    try {
                        var packet = packetReader.getNextPacket();
                        if (packet != null) {
                            Map<String, String> packetData = PacketParser.parsePacket(packet.toString());
                            if (packetData != null) {
                                // Only use RL if checkbox is selected
                                boolean allowed = true;
                                if (rlEnabledCheckbox.isSelected()) {
                                    allowed = idpsController.processPacket(packetData);
                                }

                                if (allowed) {
                                    // Continuer avec le traitement normal si le paquet est autorisé
                                SwingUtilities.invokeLater(() -> {
                                    if (shouldDisplayPacket(packetData)) {
                                        packetArea.append(formatPacketData(packetData) + "\n");
                                        packetArea.setCaretPosition(packetArea.getDocument().getLength());
                                    }
                                    updateStatistics(packetData);
                                });
                                }
                            }
                        }
                    } catch (Exception e) {
                        if (isCapturing) {
                            SwingUtilities.invokeLater(
                                    () -> insertText(logArea, "Error reading packet: " + e.getMessage() + "\n"));
                        }
                    }
                }
            });
            captureThread.start();
            
            buttonStart.setEnabled(false);
            buttonStop.setEnabled(true);
            interfaceComboBox.setEnabled(false);
            protocolComboBox.setEnabled(false);
            rlEnabledCheckbox.setEnabled(false);
            statusLabel.setText("Status: Capturing");
            
            // Enable simulation buttons when capture starts
            simulateDdosButton.setEnabled(true);
            simulateSqlInjectionButton.setEnabled(true);
            simulatePortScanButton.setEnabled(true);
            testSnortRulesButton.setEnabled(true);

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error starting capture: " + e.getMessage());
        }
    }

    private boolean shouldDisplayPacket(Map<String, String> packetData) {
        if (selectedProtocol.equals("ALL")) {
            return true;
        }
        
        String protocol = packetData.get("protocol");
        if (protocol == null) {
            return false;
        }
        
        switch (selectedProtocol) {
            case "TCP":
                return protocol.equals("TCP");
            case "UDP":
                return protocol.equals("UDP");
            case "HTTP":
                return protocol.equals("TCP") && 
                       (packetData.get("dstPort").equals("80") || 
                        packetData.get("srcPort").equals("80"));
            case "HTTPS":
                return protocol.equals("TCP") && 
                       (packetData.get("dstPort").equals("443") || 
                        packetData.get("srcPort").equals("443"));
            default:
                return true;
        }
    }

    private void stopCapture() {
        if (packetReader != null) {
            isCapturing = false;
            if (captureThread != null) {
                captureThread.interrupt();
            }
            packetReader.close();
            
            buttonStart.setEnabled(true);
            buttonStop.setEnabled(false);
            interfaceComboBox.setEnabled(true);
            protocolComboBox.setEnabled(true);
            rlEnabledCheckbox.setEnabled(true);
            statusLabel.setText("Status: Stopped");

            // Disable simulation buttons when capture stops
            simulateDdosButton.setEnabled(false);
            simulateSqlInjectionButton.setEnabled(false);
            simulatePortScanButton.setEnabled(false);
            testSnortRulesButton.setEnabled(false);

            // Stop any running simulations
            if (simulationExecutor != null) {
                simulationExecutor.shutdownNow();
            }
        }
    }

    private void exitApplication() {
        if (isCapturing) {
            stopCapture();
        }
        try {
            if (logWriter != null) {
                logWriter.close();
            }
        } catch (IOException e) {
            System.err.println("Error closing log file: " + e.getMessage());
        }
        System.exit(0);
    }

    private String formatPacketData(Map<String, String> packetData) {
        StringBuilder sb = new StringBuilder();
        sb.append("Packet Details:\n");
        for (Map.Entry<String, String> entry : packetData.entrySet()) {
            sb.append(String.format("  %s: %s\n", entry.getKey(), entry.getValue()));
        }
        return sb.toString();
    }

    private void setupListeners() {
        buttonStart.addActionListener(e -> startCapture());
        buttonStop.addActionListener(e -> stopCapture());
        buttonExit.addActionListener(e -> exitApplication());
        protocolComboBox.addActionListener(e -> {
            selectedProtocol = (String) protocolComboBox.getSelectedItem();
        });
    }

    private void loadNetworkInterfaces() {
        try {
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            for (PcapNetworkInterface device : devices) {
                interfaceComboBox.addItem(device.getName() + " (" + device.getDescription() + ")");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error loading network interfaces: " + e.getMessage());
        }
    }

    /**
     * Met à jour l'affichage avec les données d'un nouveau paquet
     * 
     * @param packetData Les données du paquet à afficher
     */
    public void updateDisplay(Map<String, String> packetData) {
        if (packetData == null) {
            LOGGER.warning("Received null packet data in updateDisplay");
            return;
        }

        lastDisplayedPacket = new HashMap<>(packetData);

        SwingUtilities.invokeLater(() -> {
            // Mettre à jour la zone des paquets
            if (shouldDisplayPacket(packetData)) {
                packetArea.append(formatPacketData(packetData) + "\n");
                packetArea.setCaretPosition(packetArea.getDocument().getLength());
            }

            // Vérifier explicitement les règles
            List<Rule> matchedRules = ruleEngine.getMatchingRules(packetData);
            LOGGER.info("Found " + matchedRules.size() + " matching rules for packet");

            for (Rule rule : matchedRules) {
                LOGGER.info("Processing matched rule: " + rule.getOptions().get("msg"));
                String severity = rule.getOption("severity");
                Alert alert = new Alert(
                    AlertType.RULE_MATCH,
                    Severity.valueOf(severity),
                    rule.getOption("msg"),
                    new HashMap<>(packetData)
                );
                displayAlert(alert);
            }

            // Mettre à jour les statistiques
            updateStatistics(packetData);
        });
    }
////////////////////////////////
    /**
     * Récupère le dernier paquet affiché
     * 
     * @return Les données du dernier paquet affiché
     */
    public Map<String, String> getLastDisplayedPacket() {
        return lastDisplayedPacket != null ? new HashMap<>(lastDisplayedPacket) : null;
    }

    private void simulateXssAttack() {
                Map<String, String> packet = new HashMap<>();
                packet.put("srcIP", "192.168.1." + random.nextInt(255));
                packet.put("destIP", "192.168.1.1");
                packet.put("srcPort", String.valueOf(random.nextInt(65535)));
                packet.put("destPort", "80");
                packet.put("protocol", "TCP");
        String xssPayload = "<script>alert('XSS')</script>";
        packet.put("data", xssPayload);
                updateDisplay(packet);
    }

    private void simulateSqlInjection() {
        Map<String, String> packet = new HashMap<>();
        packet.put("srcIP", "192.168.1." + random.nextInt(255));
        packet.put("destIP", "192.168.1.1");
        packet.put("srcPort", String.valueOf(random.nextInt(65535)));
        packet.put("destPort", "80");
        packet.put("protocol", "TCP");
        String sqliPayload = "UNION SELECT password FROM users WHERE '1'='1' --";
        packet.put("data", sqliPayload);
        packet.put("payload", sqliPayload); // Pour matcher les règles qui attendent 'payload'
        updateDisplay(packet);
    }

    private void simulatePortScan() {
        String srcIP = "192.168.1.200"; // Fixe pour la simulation
        for (int i = 0; i < 3; i++) {
            Map<String, String> packet = new HashMap<>();
            packet.put("srcIP", srcIP);
            packet.put("destIP", "192.168.1.1");
            packet.put("srcPort", String.valueOf(40000 + i));
            packet.put("destPort", String.valueOf(80 + i)); // ports différents
            packet.put("protocol", "TCP");
            packet.put("flags", "SYN");
            updateDisplay(packet);
            try { Thread.sleep(500); } catch (InterruptedException e) { /* ignore */ }
        }
    }

    private void testSnortRules() {
        // Ajouter une règle de test simple
        Rule testRule = new Rule();
        testRule.setProtocol("ICMP");
        testRule.setSourceIp("any");
        testRule.setDestinationIp("any");
        testRule.addOption("content", "AAAA");
        testRule.addOption("msg", "Test ICMP Alert");
        testRule.addOption("severity", "HIGH");
        testRule.addOption("sid", "1000001");
        ruleEngine.addRule(testRule);

        LOGGER.info("Starting Snort rules test...");
        LOGGER.info("Number of loaded rules: " + ruleEngine.getRules().size());

        // Test avec la règle simple d'abord
        simulateTestICMP();
        try { Thread.sleep(500); } catch (InterruptedException e) { /* ignore */ }
        
        // Puis les autres simulations
        simulateSnortTFNProbe();
        try { Thread.sleep(500); } catch (InterruptedException e) { /* ignore */ }
        
        simulateSnortTFN2K();
        try { Thread.sleep(500); } catch (InterruptedException e) { /* ignore */ }
        
        simulateSnortTrin00();
    }

    private void simulateTestICMP() {
        LOGGER.info("Simulating test ICMP packet...");
        Map<String, String> packet = new HashMap<>();
        packet.put("srcIP", "192.168.1." + random.nextInt(255));
        packet.put("destIP", "192.168.1.1");
        packet.put("protocol", "ICMP");
        packet.put("data", "AAAA");
        
        LOGGER.info("Generated test packet: " + packet);
        
        // Vérifier explicitement les règles avant updateDisplay
        List<Rule> matchedRules = ruleEngine.getMatchingRules(packet);
        LOGGER.info("Matched rules for test packet: " + matchedRules.size());
        
            for (Rule rule : matchedRules) {
            LOGGER.info("Rule matched: " + rule.getOptions().get("msg"));
                Alert alert = new Alert(
                    AlertType.RULE_MATCH,
                    Severity.valueOf(rule.getOption("severity")),
                rule.getOption("msg"),
                packet
                );
            displayAlert(alert);
        }
        
        // Mise à jour de l'affichage
        updateDisplay(packet);
    }

    private void simulateSnortTFNProbe() {
        Map<String, String> packet = new HashMap<>();
        packet.put("srcIP", "192.168.1." + random.nextInt(255));
        packet.put("destIP", "192.168.1.1");
        packet.put("protocol", "ICMP");
        packet.put("icmp_id", "678");
        packet.put("icmp_type", "8");
        packet.put("data", "1234");
        
        // Mise à jour de l'affichage et vérification des règles
        updateDisplay(packet);
    }

    private void simulateSnortTFN2K() {
        Map<String, String> packet = new HashMap<>();
        packet.put("srcIP", "192.168.1." + random.nextInt(255));
        packet.put("destIP", "192.168.1.1");
        packet.put("protocol", "ICMP");
        packet.put("icmp_id", "0");
        packet.put("icmp_type", "0");
        packet.put("data", "AAAAAAAAAA");
        
        // Mise à jour de l'affichage et vérification des règles
        updateDisplay(packet);
    }

    private void simulateSnortTrin00() {
        Map<String, String> packet = new HashMap<>();
        packet.put("srcIP", "192.168.1." + random.nextInt(255));
        packet.put("destIP", "192.168.1.1");
        packet.put("protocol", "UDP");
        packet.put("srcPort", String.valueOf(random.nextInt(65535)));
        packet.put("destPort", "31335");
        packet.put("data", "PONG");
        
        // Mise à jour de l'affichage et vérification des règles
        updateDisplay(packet);
    }

    private void initializeSnortRules() {
        // TFN Probe Rule
        Rule tfnRule = new Rule();
        tfnRule.setProtocol("ICMP");
        tfnRule.setSourceIp("any");
        tfnRule.setDestinationIp("any");
        tfnRule.addOption("icmp_id", "678");
        tfnRule.addOption("icmp_type", "8");
        tfnRule.addOption("content", "1234");
        tfnRule.addOption("msg", "PROTOCOL-ICMP TFN Probe");
        tfnRule.addOption("severity", "HIGH");
        ruleEngine.addRule(tfnRule);

        // TFN2K Rule
        Rule tfn2kRule = new Rule();
        tfn2kRule.setProtocol("ICMP");
        tfn2kRule.setSourceIp("any");
        tfn2kRule.setDestinationIp("any");
        tfn2kRule.addOption("icmp_id", "0");
        tfn2kRule.addOption("icmp_type", "0");
        tfn2kRule.addOption("content", "AAAAAAAAAA");
        tfn2kRule.addOption("msg", "PROTOCOL-ICMP tfn2k icmp possible communication");
        tfn2kRule.addOption("severity", "HIGH");
        ruleEngine.addRule(tfn2kRule);

        // Trin00 Rule
        Rule trin00Rule = new Rule();
        trin00Rule.setProtocol("UDP");
        trin00Rule.setSourceIp("any");
        trin00Rule.setDestinationIp("any");
        trin00Rule.setDestinationPort("31335");
        trin00Rule.addOption("content", "PONG");
        trin00Rule.addOption("msg", "MALWARE-OTHER Trin00 Daemon to Master PONG message detected");
        trin00Rule.addOption("severity", "CRITICAL");
        ruleEngine.addRule(trin00Rule);

        // Exemple de règle de test
        Rule testMaliciousRule = new Rule();
        testMaliciousRule.setProtocol("TCP");
        testMaliciousRule.setSourceIp("any");
        testMaliciousRule.setDestinationIp("any");
        testMaliciousRule.setDestinationPort("80");
        testMaliciousRule.addOption("malicious", "true"); // Ajoutez cette option
        testMaliciousRule.addOption("msg", "Test Malicious Rule");
        testMaliciousRule.addOption("severity", "HIGH");
        ruleEngine.addRule(testMaliciousRule);
    }

    private void showActiveRules() {
        RuleEngine ruleEngine = new RuleEngine(); // Assurez-vous que cela correspond à votre logique
        List<Rule> activeRules = ruleEngine.getRules(); // Récupérer les règles actives

        StringBuilder rulesDisplay = new StringBuilder();
        for (Rule rule : activeRules) {
            // Vérifiez si la règle contient un message indiquant qu'elle détecte un malware
            String msg = rule.getOptions().get("msg");
            if (msg != null && (msg.contains("MALWARE") || msg.contains("PROTOCOL-ICMP"))) {
                rulesDisplay.append(msg).append("\n"); // Affichez le message de la règle
            }
        }

        // Afficher les règles dans un dialogue avec défilement
        JTextArea rulesTextArea = new JTextArea(rulesDisplay.toString());
        rulesTextArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(rulesTextArea);
        scrollPane.setPreferredSize(new Dimension(400, 300)); // Ajustez la taille selon vos besoins

        JOptionPane.showMessageDialog(this, scrollPane, "Règles Actives", JOptionPane.INFORMATION_MESSAGE);
    }
}
// Add email button


