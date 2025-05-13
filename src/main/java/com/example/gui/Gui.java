package com.example.gui;

import com.example.gui.components.*;
import com.example.util.PacketReader;
import com.example.util.PacketReaderFactory;
import com.example.detection.RuleEngine;
import com.example.detection.Alert;
import com.example.rl.RLAgent;
import com.example.rl.Environment;
import com.example.rl.State;
import com.example.rl.Action;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Gui extends JFrame {
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

    public Gui() {
        setTitle("Network Intrusion Detection System");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1200, 800);
        setLocationRelativeTo(null);
        setModernBlueTheme();
        initializeComponents();
        setupLayout();
        setupEventListeners();
        initializeSystems();
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
    }

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

    private void simulateXssAttack() {
        // Implementation for XSS attack simulation
        logPanel.appendText("Simulating XSS attack...\n");
    }

    private void simulateSqlInjection() {
        // Implementation for SQL injection simulation
        logPanel.appendText("Simulating SQL injection attack...\n");
    }

    private void simulatePortScan() {
        // Implementation for port scan simulation
        logPanel.appendText("Simulating port scan attack...\n");
    }

    private void testSnortRules() {
        // Implementation for Snort rules testing
        logPanel.appendText("Testing Snort rules...\n");
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

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Gui gui = new Gui();
            gui.setVisible(true);
        });
    }
}


