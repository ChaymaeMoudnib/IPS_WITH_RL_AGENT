package com.example.gui;

import com.example.gui.components.*;
import com.example.util.PacketReader;
import com.example.util.PacketReaderFactory;
import com.example.detection.RuleEngine;
import com.example.detection.Alert;
import com.example.detection.AlertType;
import com.example.detection.Severity;
import com.example.rl.RLAgent;
import com.example.rl.Environment;
import com.example.rl.State;
import com.example.rl.Action;
import com.example.util.Rule;
import com.example.util.EmailSender;
import com.example.util.EmailConfig;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.text.SimpleDateFormat;

public class Gui extends JFrame {
    private static final Logger LOGGER = Logger.getLogger(Gui.class.getName());
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private ControlPanel controlPanel;
    private SimulationPanel simulationPanel;
    private PacketDisplayPanel packetDisplayPanel;
    private TrafficStatisticsPanel trafficStatisticsPanel;
    private RLStatisticsPanel rlStatisticsPanel;
    private LogPanel logPanel;
    private RLDecisionsPanel rlDecisionsPanel;

    private PacketReader reader;
    private RuleEngine ruleEngine;
    private RLAgent rlAgent;
    private Environment env;
    private AtomicBoolean isCapturing = new AtomicBoolean(false);
    private AtomicInteger allowedCount = new AtomicInteger(0);
    private AtomicInteger blockedCount = new AtomicInteger(0);

    private static final Color PRIMARY_BLUE = new Color(33, 97, 140);
    private static final Color LIGHT_BLUE = new Color(174, 214, 241);
    private static final Color PANEL_BG = new Color(236, 245, 251);
    private static final Color BORDER_BLUE = new Color(52, 152, 219);
    private static final Font HEADER_FONT = new Font("Segoe UI", Font.BOLD, 18);
    private static final Font LABEL_FONT = new Font("Segoe UI", Font.PLAIN, 14);
    private static final Font BUTTON_FONT = new Font("Segoe UI", Font.BOLD, 13);

    private Map<String, String> lastDisplayedPacket;
    private JButton showActiveRulesButton;
    private EmailSender emailSender;
    private EmailConfig emailConfig;
    private JButton configureEmailButton;
    private boolean emailAlertsEnabled = false;

    private JButton testSnortRulesButton;
    private Random random = new Random();

    public Gui() {
        setTitle("Network Intrusion Detection System");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1200, 800);
        setLocationRelativeTo(null);
        setModernBlueTheme();
        
        // Initialize buttons first
        showActiveRulesButton = new JButton("Show Active Rules");
        showActiveRulesButton.setFont(BUTTON_FONT);
        showActiveRulesButton.setBackground(LIGHT_BLUE);
        showActiveRulesButton.setForeground(PRIMARY_BLUE);
        showActiveRulesButton.setFocusPainted(false);
        showActiveRulesButton.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_BLUE),
            BorderFactory.createEmptyBorder(5, 15, 5, 15)
        ));
        
        configureEmailButton = new JButton("Configure Email Alerts");
        configureEmailButton.setFont(BUTTON_FONT);
        configureEmailButton.setBackground(LIGHT_BLUE);
        configureEmailButton.setForeground(PRIMARY_BLUE);
        configureEmailButton.setFocusPainted(false);
        configureEmailButton.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_BLUE),
            BorderFactory.createEmptyBorder(5, 15, 5, 15)
        ));
        
        initializeComponents();
        setupLayout();
        setupEventListeners();
        initializeSystems();
        initializeEmailSettings();
        
        // Create and add bottom control panel
        JPanel bottomControlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));
        bottomControlPanel.setBackground(PANEL_BG);
        bottomControlPanel.setBorder(new EmptyBorder(10, 0, 10, 0));
        bottomControlPanel.add(showActiveRulesButton);
        bottomControlPanel.add(configureEmailButton);
        add(bottomControlPanel, BorderLayout.SOUTH);
    }

    private void setModernBlueTheme() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // fallback
        }
        getContentPane().setBackground(PANEL_BG);
        // Set global UI colors
        UIManager.put("Panel.background", PANEL_BG);
        UIManager.put("Button.background", LIGHT_BLUE);
        UIManager.put("Button.foreground", PRIMARY_BLUE);
        UIManager.put("Button.font", BUTTON_FONT);
        UIManager.put("Label.foreground", PRIMARY_BLUE);
        UIManager.put("Label.font", LABEL_FONT);
        UIManager.put("TitledBorder.border", BorderFactory.createLineBorder(BORDER_BLUE, 2));
        UIManager.put("TitledBorder.titleColor", PRIMARY_BLUE);
        UIManager.put("TitledBorder.font", HEADER_FONT);
        UIManager.put("TextArea.background", Color.WHITE);
        UIManager.put("TextArea.foreground", new Color(30, 30, 30));
        UIManager.put("TextArea.font", LABEL_FONT);
        UIManager.put("ScrollPane.border", BorderFactory.createLineBorder(BORDER_BLUE, 1));
        UIManager.put("ComboBox.background", LIGHT_BLUE);
        UIManager.put("ComboBox.foreground", PRIMARY_BLUE);
        UIManager.put("ComboBox.font", LABEL_FONT);
        UIManager.put("CheckBox.background", PANEL_BG);
        UIManager.put("CheckBox.foreground", PRIMARY_BLUE);
        UIManager.put("CheckBox.font", LABEL_FONT);
    }

    private void initializeComponents() {
        controlPanel = new ControlPanel();
        simulationPanel = new SimulationPanel();
        packetDisplayPanel = new PacketDisplayPanel();
        trafficStatisticsPanel = new TrafficStatisticsPanel();
        rlStatisticsPanel = new RLStatisticsPanel();
        logPanel = new LogPanel();
        rlDecisionsPanel = new RLDecisionsPanel();
    }

    private void setupLayout() {
        setLayout(new BorderLayout());

        // Top panel with controls and simulation
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(controlPanel, BorderLayout.CENTER);
        topPanel.add(simulationPanel, BorderLayout.SOUTH);

        // Middle panel with packet display and statistics (split into two)
        JSplitPane statsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, trafficStatisticsPanel, rlStatisticsPanel);
        statsSplitPane.setResizeWeight(0.5);
        statsSplitPane.setDividerLocation(0.5);
        statsSplitPane.setDividerSize(5);
        statsSplitPane.setOneTouchExpandable(true);

        JSplitPane middleSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, packetDisplayPanel, statsSplitPane);
        middleSplitPane.setResizeWeight(0.5);
        middleSplitPane.setDividerLocation(0.5);
        middleSplitPane.setDividerSize(5);
        middleSplitPane.setOneTouchExpandable(true);

        // Bottom panel with logs and RL decisions
        JSplitPane bottomSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, logPanel, rlDecisionsPanel);
        bottomSplitPane.setResizeWeight(0.5);
        bottomSplitPane.setDividerLocation(0.5);
        bottomSplitPane.setDividerSize(5);
        bottomSplitPane.setOneTouchExpandable(true);

        // Main split pane for middle and bottom panels
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, middleSplitPane, bottomSplitPane);
        mainSplitPane.setResizeWeight(0.5);
        mainSplitPane.setDividerLocation(0.5);
        mainSplitPane.setDividerSize(5);
        mainSplitPane.setOneTouchExpandable(true);

        // Add all panels to the frame
        add(topPanel, BorderLayout.NORTH);
        add(mainSplitPane, BorderLayout.CENTER);

        // Set minimum sizes for panels
        Dimension minSize = new Dimension(400, 200);
        packetDisplayPanel.setMinimumSize(minSize);
        trafficStatisticsPanel.setMinimumSize(minSize);
        rlStatisticsPanel.setMinimumSize(minSize);
        logPanel.setMinimumSize(minSize);
        rlDecisionsPanel.setMinimumSize(minSize);
    }

    private void setupEventListeners() {
        // Control Panel events
        controlPanel.getButtonStart().addActionListener(e -> startCapture());
        controlPanel.getButtonStop().addActionListener(e -> stopCapture());
        controlPanel.getButtonExit().addActionListener(e -> System.exit(0));
        controlPanel.getProtocolComboBox().addActionListener(e -> {
            String selectedProtocol = (String) controlPanel.getProtocolComboBox().getSelectedItem();
            controlPanel.setSelectedProtocol(selectedProtocol);
        });
        controlPanel.getDarkModeToggle().addActionListener(e -> {
            boolean dark = controlPanel.getDarkModeToggle().isSelected();
            setDarkMode(dark);
        });

        // Simulation Panel events
        simulationPanel.getSimulateDdosButton().addActionListener(e -> simulateXssAttack());
        simulationPanel.getSimulateSqlInjectionButton().addActionListener(e -> simulateSqlInjection());
        simulationPanel.getSimulatePortScanButton().addActionListener(e -> simulatePortScan());
        simulationPanel.getTestSnortRulesButton().addActionListener(e -> testSnortRules());
        
        // Bottom control panel events
        showActiveRulesButton.addActionListener(e -> showActiveRules());
        configureEmailButton.addActionListener(e -> showEmailConfigDialog());
    }

    ////
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
        
        // Mettre à jour les statistiques
        trafficStatisticsPanel.updateStatistics(packet);
        
        // Créer et afficher l'alerte
        Alert alert = new Alert(
            AlertType.XSS_ATTACK,
            Severity.HIGH,
            "XSS Attack Detected!\nSource: " + packet.get("srcIP") + "\nTarget: " + packet.get("destIP") + "\nPayload: " + xssPayload,
            packet
        );
        logPanel.displayAlert(alert);
        processAlert(alert);
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
        packet.put("payload", sqliPayload);
        
        // Mettre à jour les statistiques
        trafficStatisticsPanel.updateStatistics(packet);
        
        // Créer et afficher l'alerte
        Alert alert = new Alert(
            AlertType.SQL_INJECTION,
            Severity.HIGH,
            "SQL Injection Attack Detected!\nSource: " + packet.get("srcIP") + "\nTarget: " + packet.get("destIP") + "\nPayload: " + sqliPayload,
            packet
        );
        logPanel.displayAlert(alert);
        processAlert(alert);
    }

    private void simulatePortScan() {
        String srcIP = "192.168.1.200"; // Fixe pour la simulation
        Set<String> scannedPorts = new HashSet<>();
        
        for (int i = 0; i < 3; i++) {
            Map<String, String> packet = new HashMap<>();
            packet.put("srcIP", srcIP);
            packet.put("destIP", "192.168.1.1");
            packet.put("srcPort", String.valueOf(40000 + i));
            String destPort = String.valueOf(80 + i);
            packet.put("destPort", destPort);
            packet.put("protocol", "TCP");
            packet.put("flags", "SYN");
            
            // Mettre à jour les statistiques
            trafficStatisticsPanel.updateStatistics(packet);
            
            // Ajouter le port scanné
            scannedPorts.add(destPort);
            
            try { Thread.sleep(500); } catch (InterruptedException e) { /* ignore */ }
        }
        
        // Créer et afficher l'alerte de scan de ports
        Map<String, String> alertData = new HashMap<>();
        alertData.put("srcIP", srcIP);
        alertData.put("destIP", "192.168.1.1");
        alertData.put("scannedPorts", String.join(",", scannedPorts));
        alertData.put("protocol", "TCP");
        
        Alert alert = new Alert(
            AlertType.PORT_SCAN,
            Severity.HIGH,
            "Port Scan Detected!\nSource: " + srcIP + "\nTarget: 192.168.1.1\nScanned Ports: " + String.join(", ", scannedPorts),
            alertData
        );
        logPanel.displayAlert(alert);
        processAlert(alert);
    }

    private void testSnortRules() {
        logPanel.appendText("\n=== Starting Snort Rules Testing ===\n");
        
        // Test 1: Stacheldraht DDoS Attack
        logPanel.appendText("\nTest 1: Stacheldraht DDoS Attack Detection\n");
        Map<String, String> packet1 = new HashMap<>();
        packet1.put("srcIP", "192.168.2.1");
        packet1.put("destIP", "192.168.1.1");
        packet1.put("protocol", "ICMP");
        packet1.put("icmp_id", "1000");
        packet1.put("itype", "0");
        packet1.put("icode", "0");
        packet1.put("data", "spoofworks");
        
        // Mettre à jour les statistiques
        trafficStatisticsPanel.updateStatistics(packet1);
        
        // Créer et afficher l'alerte
        Alert alert1 = new Alert(
            AlertType.DDOS_ATTACK,
            Severity.HIGH,
            "PROTOCOL-ICMP Stacheldraht client spoofworks\nRule SID: 227\nClassification: attempted-dos",
            packet1
        );
        logPanel.displayAlert(alert1);
        processAlert(alert1);
        
        try { Thread.sleep(500); } catch (InterruptedException e) { /* ignore */ }
        
        // Test 2: TFN DDoS Attack
        logPanel.appendText("\nTest 2: TFN DDoS Attack Detection\n");
        Map<String, String> packet2 = new HashMap<>();
        packet2.put("srcIP", "192.168.2.2");
        packet2.put("destIP", "192.168.1.1");
        packet2.put("protocol", "ICMP");
        packet2.put("icmp_id", "678");
        packet2.put("itype", "8");
        packet2.put("data", "1234");
        
        // Mettre à jour les statistiques
        trafficStatisticsPanel.updateStatistics(packet2);
        
        // Créer et afficher l'alerte
        Alert alert2 = new Alert(
            AlertType.DDOS_ATTACK,
            Severity.HIGH,
            "PROTOCOL-ICMP TFN client command BE\nRule SID: 228\nClassification: attempted-dos",
            packet2
        );
        logPanel.displayAlert(alert2);
        processAlert(alert2);
        
        try { Thread.sleep(500); } catch (InterruptedException e) { /* ignore */ }
        
        // Test 3: Shaft DDoS Handler
        logPanel.appendText("\nTest 3: Shaft DDoS Handler Detection\n");
        Map<String, String> packet3 = new HashMap<>();
        packet3.put("srcIP", "192.168.1.1");
        packet3.put("srcPort", "20432");
        packet3.put("destIP", "192.168.2.3");
        packet3.put("destPort", "12345");
        packet3.put("protocol", "TCP");
        packet3.put("data", "login:");
        
        // Mettre à jour les statistiques
        trafficStatisticsPanel.updateStatistics(packet3);
        
        // Créer et afficher l'alerte
        Alert alert3 = new Alert(
            AlertType.MALWARE_TRAFFIC,
            Severity.HIGH,
            "MALWARE-OTHER shaft client login to handler\nRule SID: 230\nClassification: attempted-dos",
            packet3
        );
        logPanel.displayAlert(alert3);
        processAlert(alert3);
        
        logPanel.appendText("\n=== Snort Rules Testing Completed ===\n");
    }

   
    /// 

    private void initializeSystems() {
        ruleEngine = new RuleEngine();
        rlAgent = new RLAgent();
        env = new Environment();

        try {
            rlAgent.loadModel("trained_model.rl");
            logPanel.appendText("RL model loaded successfully\n");
        } catch (Exception e) {
            logPanel.appendText("Error loading RL model: " + e.getMessage() + "\n");
        }
    }

    private void startCapture() {
        if (isCapturing.get()) return;

        String selectedInterface = controlPanel.getSelectedInterface();
        if (selectedInterface == null) {
            JOptionPane.showMessageDialog(this, "Please select a network interface");
            return;
        }

        try {
            reader = PacketReaderFactory.createPacketReader("live", selectedInterface);
            isCapturing.set(true);
            
            // Disable interface selection and related controls
            controlPanel.getInterfaceComboBox().setEnabled(false);
            controlPanel.getProtocolComboBox().setEnabled(false);
            controlPanel.getButtonStart().setEnabled(false);
            controlPanel.getButtonStop().setEnabled(true);
            simulationPanel.setSimulationEnabled(true);
            controlPanel.setStatus("Capturing...");

            new Thread(this::captureLoop).start();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error starting capture: " + e.getMessage());
            stopCapture();
        }
    }

    private void stopCapture() {
        isCapturing.set(false);
        if (reader != null) {
            reader.close();
        }
        
        // Re-enable interface selection and related controls
        controlPanel.getInterfaceComboBox().setEnabled(true);
        controlPanel.getProtocolComboBox().setEnabled(true);
        controlPanel.getButtonStart().setEnabled(true);
        controlPanel.getButtonStop().setEnabled(false);
        simulationPanel.setSimulationEnabled(false);
        controlPanel.setStatus("Stopped");
    }

    private void captureLoop() {
        while (isCapturing.get()) {
            try {
                Packet packet = reader.getNextPacket();
                if (packet != null) {
                    processPacket(packet);
                }
            } catch (Exception e) {
                logPanel.appendText("Error processing packet: " + e.getMessage() + "\n");
                if (e instanceof IllegalStateException) {
                    // Handle interface closed or other fatal errors
                    stopCapture();
                    JOptionPane.showMessageDialog(this, 
                        "Packet capture stopped due to error: " + e.getMessage(),
                        "Capture Error",
                        JOptionPane.ERROR_MESSAGE);
                    break;
                }
            }
        }
    }

    private void processPacket(Packet packet) {
        try {
            State state = env.extractState(packet);
            if (state == null) {
                return; // Skip invalid packets
            }

            Map<String, String> packetData = new HashMap<>();
            packetData.put("protocol", state.getProtocol());
            packetData.put("srcPort", state.getSrcPort());
            packetData.put("srcIP", state.getSrcIP());
            packetData.put("destPort", state.getDestPort());
            packetData.put("destIP", state.getDestIP());

            // Update packet display
            packetDisplayPanel.appendPacket(packetData);

            // Update traffic statistics
            trafficStatisticsPanel.updateStatistics(packetData);

            // Check rules
            boolean ruleMatch = ruleEngine.matches(packetData);
            if (ruleMatch) {
                Alert alert = ruleEngine.getLastAlert();
                logPanel.displayAlert(alert);
                processAlert(alert);
                trafficStatisticsPanel.incrementAlertCount();
            }

            // Check for anomalies
            Alert anomalyAlert = env.getAnomalyDetector().detectAnomaly(packetData);
            if (anomalyAlert != null) {
                logPanel.displayAlert(anomalyAlert);
                processAlert(anomalyAlert);
                trafficStatisticsPanel.incrementAlertCount();
            }

            // RL decision if enabled
            if (controlPanel.getRlEnabledCheckbox().isSelected()) {
                Action rlAction = rlAgent.getAction(state);
                boolean isAllowed = rlAction.isAllowed();

                if (isAllowed) {
                    allowedCount.incrementAndGet();
                } else {
                    blockedCount.incrementAndGet();
                }

                String decision = String.format("[%s] %s:%s -> %s:%s (%s) - %s",
                        state.getProtocol(),
                        state.getSrcIP(),
                        state.getSrcPort(),
                        state.getDestIP(),
                        state.getDestPort(),
                        state.getData(),
                        isAllowed ? "ALLOWED" : "BLOCKED");

                rlDecisionsPanel.appendDecision(decision);

                // Update RL statistics
                Map<String, Object> rlStats = new HashMap<>();
                rlStats.put("allowedCount", allowedCount.get());
                rlStats.put("blockedCount", blockedCount.get());
                rlStats.put("accuracy", calculateAccuracy());
                rlStatisticsPanel.updateRLStats(rlStats);
            }
        } catch (Exception e) {
            logPanel.appendText("Error processing packet data: " + e.getMessage() + "\n");
        }
    }

    private double calculateAccuracy() {
        int total = allowedCount.get() + blockedCount.get();
        return total > 0 ? (double) allowedCount.get() / total * 100 : 0;
    }


    private void setDarkMode(boolean dark) {
        Color bg = dark ? new Color(34, 40, 49) : Color.WHITE;
        Color panelBg = dark ? new Color(44, 52, 62) : new Color(248, 249, 251);
        Color border = dark ? new Color(60, 70, 80) : new Color(230, 230, 230);
        Color header = dark ? new Color(0, 173, 238) : new Color(33, 97, 140);
        Color text = dark ? new Color(220, 220, 220) : new Color(30, 30, 30);
        Color subText = dark ? new Color(180, 180, 180) : new Color(120, 144, 156);
        Color buttonBg = dark ? new Color(55, 65, 80) : new Color(240, 240, 240);
        Color buttonFg = dark ? new Color(200, 220, 255) : new Color(33, 97, 140);
        Color toggleBg = dark ? new Color(0, 173, 238) : new Color(230, 230, 230);
        Color toggleFg = dark ? Color.WHITE : new Color(33, 97, 140);

        getContentPane().setBackground(bg);

        // Control Panel
        controlPanel.setBackground(bg);
        controlPanel.getInterfaceComboBox().setBackground(panelBg);
        controlPanel.getInterfaceComboBox().setForeground(text);
        controlPanel.getProtocolComboBox().setBackground(panelBg);
        controlPanel.getProtocolComboBox().setForeground(text);
        controlPanel.getButtonStart().setBackground(buttonBg);
        controlPanel.getButtonStart().setForeground(buttonFg);
        controlPanel.getButtonStop().setBackground(buttonBg);
        controlPanel.getButtonStop().setForeground(buttonFg);
        controlPanel.getButtonExit().setBackground(buttonBg);
        controlPanel.getButtonExit().setForeground(buttonFg);
        controlPanel.getRlEnabledCheckbox().setBackground(bg);
        controlPanel.getRlEnabledCheckbox().setForeground(text);
        controlPanel.getStatusLabel().setForeground(dark ? new Color(0, 173, 238) : new Color(0, 100, 0));
        controlPanel.getDarkModeToggle().setBackground(toggleBg);
        controlPanel.getDarkModeToggle().setForeground(toggleFg);
        controlPanel.getDarkModeToggle().setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(dark ? new Color(0, 173, 238) : new Color(200, 200, 200)),
            BorderFactory.createEmptyBorder(5, 15, 5, 15)
        ));

        // Simulation Panel
        simulationPanel.setBackground(bg);
        simulationPanel.getSimulateDdosButton().setBackground(buttonBg);
        simulationPanel.getSimulateDdosButton().setForeground(buttonFg);
        simulationPanel.getSimulateSqlInjectionButton().setBackground(buttonBg);
        simulationPanel.getSimulateSqlInjectionButton().setForeground(buttonFg);
        simulationPanel.getSimulatePortScanButton().setBackground(buttonBg);
        simulationPanel.getSimulatePortScanButton().setForeground(buttonFg);
        simulationPanel.getTestSnortRulesButton().setBackground(buttonBg);
        simulationPanel.getTestSnortRulesButton().setForeground(buttonFg);
        simulationPanel.setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.LineBorder(border, 1, true),
            new javax.swing.border.EmptyBorder(10, 10, 10, 10)
        ));

        // Packet Display Panel
        packetDisplayPanel.setBackground(bg);
        packetDisplayPanel.getPacketArea().setBackground(panelBg);
        packetDisplayPanel.getPacketArea().setForeground(text);
        packetDisplayPanel.getHeaderLabel().setForeground(header);
        packetDisplayPanel.setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.LineBorder(border, 1, true),
            new javax.swing.border.EmptyBorder(18, 18, 18, 18)
        ));

        // Traffic Statistics Panel
        trafficStatisticsPanel.setBackground(bg);
        trafficStatisticsPanel.getStatsArea().setBackground(panelBg);
        trafficStatisticsPanel.getStatsArea().setForeground(text);
        trafficStatisticsPanel.getHeaderLabel().setForeground(header);
        trafficStatisticsPanel.getLastUpdateLabel().setForeground(subText);
        trafficStatisticsPanel.setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.LineBorder(border, 1, true),
            new javax.swing.border.EmptyBorder(18, 18, 18, 18)
        ));

        // RL Statistics Panel
        rlStatisticsPanel.setBackground(bg);
        rlStatisticsPanel.getStatsArea().setBackground(panelBg);
        rlStatisticsPanel.getStatsArea().setForeground(text);
        rlStatisticsPanel.getHeaderLabel().setForeground(header);
        rlStatisticsPanel.getLastUpdateLabel().setForeground(subText);
        rlStatisticsPanel.setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.LineBorder(border, 1, true),
            new javax.swing.border.EmptyBorder(18, 18, 18, 18)
        ));

        // Log Panel
        logPanel.setBackground(bg);
        logPanel.getLogArea().setBackground(panelBg);
        logPanel.getLogArea().setForeground(text);
        logPanel.getHeaderLabel().setForeground(header);
        logPanel.setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.LineBorder(border, 1, true),
            new javax.swing.border.EmptyBorder(18, 18, 18, 18)
        ));

        // RL Decisions Panel
        rlDecisionsPanel.setBackground(bg);
        rlDecisionsPanel.getRLDecisionsArea().setBackground(panelBg);
        rlDecisionsPanel.getRLDecisionsArea().setForeground(text);
        rlDecisionsPanel.getHeaderLabel().setForeground(header);
        rlDecisionsPanel.setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.LineBorder(border, 1, true),
            new javax.swing.border.EmptyBorder(18, 18, 18, 18)
        ));

        SwingUtilities.updateComponentTreeUI(this);
    }

    public void setRuleEngine(RuleEngine ruleEngine) {
        this.ruleEngine = ruleEngine;
    }

    public PacketDisplayPanel getPacketDisplayPanel() {
        return packetDisplayPanel;
    }

    private void processAlert(Alert alert) {
        if (alert == null) return;  // Protection contre les alertes null
        
        // Vérifier si l'alerte est de sévérité HIGH ou CRITICAL
        boolean shouldSendEmail = emailAlertsEnabled && emailSender != null && 
            (alert.getSeverity() == Severity.HIGH || alert.getSeverity() == Severity.CRITICAL);
            
        if (shouldSendEmail) {
            LOGGER.info("Processing " + alert.getSeverity() + " severity alert for email notification");
            
            StringBuilder emailContent = new StringBuilder();
            emailContent.append("High/Critical Severity Alert Detected!\n\n");
            emailContent.append("Time: ").append(dateFormat.format(new Date())).append("\n");
            emailContent.append("Severity: ").append(alert.getSeverity()).append("\n");
            emailContent.append("Message: ").append(alert.getMessage()).append("\n\n");

            Map<String, String> packetData = alert.getPacketData();
            if (packetData != null) {
                emailContent.append("Attack Details:\n");
                emailContent.append("Source: ").append(packetData.get("srcIP"))
                          .append(":").append(packetData.get("srcPort")).append("\n");
                emailContent.append("Destination: ").append(packetData.get("destIP"))
                          .append(":").append(packetData.get("destPort")).append("\n");
                emailContent.append("Protocol: ").append(packetData.get("protocol")).append("\n");
                if (packetData.get("data") != null) {
                    emailContent.append("Data: ").append(packetData.get("data")).append("\n");
                }
            }

            // Send email asynchronously
            new Thread(() -> {
                try {
                    LOGGER.info("Attempting to send alert email");
                    emailSender.sendAlertEmail(
                        "IDS " + alert.getSeverity() + " Severity Alert: " + alert.getMessage(),
                        emailContent.toString()
                    );
                    LOGGER.info("Alert email sent successfully");
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Failed to send alert email", e);
                }
            }).start();
        } else {
            if (!emailAlertsEnabled) {
                LOGGER.info("Email alerts are disabled");
            } else if (emailSender == null) {
                LOGGER.warning("Email sender is not configured");
            } else {
                LOGGER.info("Alert severity " + alert.getSeverity() + " does not meet threshold for email notification");
            }
        }
    }

    private void initializeSnortRules() {
        showActiveRulesButton = new JButton("Show Active Rules");
        showActiveRulesButton.addActionListener(e -> showActiveRules());

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
        List<Rule> activeRules = ruleEngine.getRules();

        StringBuilder rulesDisplay = new StringBuilder();
        for (Rule rule : activeRules) {
            String msg = rule.getOptions().get("msg");
            if (msg != null && (msg.contains("MALWARE") || msg.contains("PROTOCOL-ICMP"))) {
                rulesDisplay.append(msg).append("\n");
            }
        }

        JTextArea rulesTextArea = new JTextArea(rulesDisplay.toString());
        rulesTextArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(rulesTextArea);
        scrollPane.setPreferredSize(new Dimension(400, 300));

        JOptionPane.showMessageDialog(this, scrollPane, "Active Rules", JOptionPane.INFORMATION_MESSAGE);
    }

    private void initializeEmailSettings() {
        // Initialize email configuration
        emailConfig = new EmailConfig();
        
        // If we have valid saved config, create the email sender
        if (emailConfig.hasValidConfig()) {
            try {
                emailSender = EmailSender.createDefaultSender(
                    emailConfig.getUsername(),
                    emailConfig.getPassword(),
                    emailConfig.getAdminEmail()
                );
                emailAlertsEnabled = emailConfig.isEnabled();
                LOGGER.info("Email sender initialized from saved configuration");
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to initialize email sender from config", e);
            }
        }

        configureEmailButton = new JButton("Configure Email Alerts");
        configureEmailButton.addActionListener(e -> showEmailConfigDialog());
    }

    private void showEmailConfigDialog() {
        JDialog dialog = new JDialog(this, "Email Configuration", true);
        dialog.setLayout(new GridLayout(7, 2, 5, 5));

        // Add fields with default values if previously configured
        JTextField emailField = new JTextField(emailConfig.getUsername(), 20);
        JPasswordField passwordField = new JPasswordField(emailConfig.getPassword(), 20);
        JTextField adminEmailField = new JTextField(emailConfig.getAdminEmail(), 20);
        JCheckBox enableEmailsCheckbox = new JCheckBox("Enable Email Alerts", emailConfig.isEnabled());
        
        // Status label for feedback
        JLabel statusLabel = new JLabel("");
        statusLabel.setForeground(Color.RED);

        dialog.add(new JLabel("Gmail Address:"));
        dialog.add(emailField);
        dialog.add(new JLabel("App Password:"));
        dialog.add(passwordField);
        dialog.add(new JLabel("Admin Email:"));
        dialog.add(adminEmailField);
        dialog.add(new JLabel("Enable Alerts:"));
        dialog.add(enableEmailsCheckbox);
        dialog.add(new JLabel("Status:"));
        dialog.add(statusLabel);

        JButton testButton = new JButton("Test Connection");
        JButton saveButton = new JButton("Save Configuration");
        JButton clearButton = new JButton("Clear Configuration");

        clearButton.setBackground(new Color(255, 200, 200));
        clearButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                dialog,
                "Are you sure you want to clear all email settings?\nThis action cannot be undone.",
                "Confirm Clear Configuration",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            
            if (confirm == JOptionPane.YES_OPTION) {
                try {
                    // Clear configuration
                    emailConfig.clearConfig();
                    emailSender = null;
                    emailAlertsEnabled = false;
                    
                    // Clear form fields
                    emailField.setText("");
                    passwordField.setText("");
                    adminEmailField.setText("");
                    enableEmailsCheckbox.setSelected(false);
                    
                    statusLabel.setText("Configuration cleared successfully!");
                    statusLabel.setForeground(Color.GREEN);
                    
                    // Close dialog after short delay
                    javax.swing.Timer timer = new javax.swing.Timer(1500, evt -> dialog.dispose());
                    timer.setRepeats(false);
                    timer.start();
                    
                } catch (Exception ex) {
                    LOGGER.log(Level.SEVERE, "Failed to clear configuration", ex);
                    statusLabel.setText("Error clearing configuration: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                }
            }
        });

        testButton.addActionListener(e -> {
            try {
                statusLabel.setText("Testing connection...");
                statusLabel.setForeground(Color.BLUE);
                dialog.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
                
                String email = emailField.getText().trim();
                String password = new String(passwordField.getPassword()).trim();
                String adminEmail = adminEmailField.getText().trim();
                
                // Validate inputs
                if (email.isEmpty() || password.isEmpty() || adminEmail.isEmpty()) {
                    throw new IllegalArgumentException("All fields must be filled");
                }
                
                EmailSender testSender = EmailSender.createDefaultSender(email, password, adminEmail);
                
                // Test connection first
                if (!testSender.testConnection()) {
                    throw new Exception("Connection test failed");
                }
                
                // If connection successful, try sending test email
                testSender.sendAlertEmail(
                    "IDS Test Email",
                    "This is a test email from your IDS system.\nTime: " + new Date()
                );
                
                statusLabel.setText("Test successful!");
                statusLabel.setForeground(Color.GREEN);
                
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, "Email test failed", ex);
                statusLabel.setText("Error: " + ex.getMessage());
                statusLabel.setForeground(Color.RED);
            } finally {
                dialog.setCursor(Cursor.getDefaultCursor());
            }
        });

        saveButton.addActionListener(e -> {
            try {
                statusLabel.setText("Saving configuration...");
                statusLabel.setForeground(Color.BLUE);
                dialog.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
                
                String email = emailField.getText().trim();
                String password = new String(passwordField.getPassword()).trim();
                String adminEmail = adminEmailField.getText().trim();
                
                // Create and test new email sender
                EmailSender newSender = EmailSender.createDefaultSender(email, password, adminEmail);
                if (!newSender.testConnection()) {
                    throw new Exception("Connection test failed");
                }
                
                // Update configuration
                emailConfig.setUsername(email);
                emailConfig.setPassword(password);
                emailConfig.setAdminEmail(adminEmail);
                emailConfig.setEnabled(enableEmailsCheckbox.isSelected());
                emailConfig.saveConfig();
                
                // Update email sender
                emailSender = newSender;
                emailAlertsEnabled = enableEmailsCheckbox.isSelected();
                
                statusLabel.setText("Configuration saved successfully!");
                statusLabel.setForeground(Color.GREEN);
                
                // Close dialog after short delay
                javax.swing.Timer timer = new javax.swing.Timer(1500, evt -> dialog.dispose());
                timer.setRepeats(false);
                timer.start();
                
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, "Failed to save email configuration", ex);
                statusLabel.setText("Error: " + ex.getMessage());
                statusLabel.setForeground(Color.RED);
            } finally {
                dialog.setCursor(Cursor.getDefaultCursor());
            }
        });

        // Help button with instructions
        JButton helpButton = new JButton("Help");
        helpButton.addActionListener(e -> {
            JOptionPane.showMessageDialog(dialog,
                "To configure Gmail:\n\n" +
                "1. Use your Gmail address\n" +
                "2. Create an App Password:\n" +
                "   - Go to Google Account settings\n" +
                "   - Enable 2-Step Verification\n" +
                "   - Go to Security > App Passwords\n" +
                "   - Generate a new App Password\n" +
                "3. Use the generated App Password here\n" +
                "4. Make sure to enable 'Less secure app access'\n" +
                "   in your Google Account settings",
                "Email Configuration Help",
                JOptionPane.INFORMATION_MESSAGE);
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        buttonPanel.add(testButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(helpButton);
        
        dialog.add(buttonPanel);

        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Gui gui = new Gui();
            gui.setVisible(true);
        });
    }
}


